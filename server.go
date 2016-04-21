/*
Package smtpd implements the SMTP server protocol.
*/
package smtpd

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultHostname is used in the banner greeting when Server#hostname is empty.
var DefaultHostname, _ = os.Hostname()

// Server represents an SMTP server configuration.
type Server struct {
	// Hostname to use in responses
	Hostname string

	// Set to enable STARTTLS
	// must include at least one certificate or else set GetCertificate
	TLSConfig *tls.Config

	// Set to enable PIPELINING
	Pipelining bool
}

func (s *Server) hostname() string {
	if s.Hostname != "" {
		return s.Hostname
	}
	return DefaultHostname
}

// Debug can be set to true to print SMTP traces to the default Logger in package log.
var Debug = false

// Handler should be implemented by the application for handling SMTP command
// parameters and message data on a connection.
//
// Each member can return an error to reject the command or to indicate
// processing failure. If the error text starts with a three digit status code,
// then the error text is returned as-is in the SMTP reply. If the error does
// not start with three digits, then "451 Requested action aborted: " is
// returned in the SMTP reply with the error text appended.
type Handler interface {
	// Connect is called after connecting
	Connect(source string) error

	// Hello is called after EHLO/HELO
	Hello(hostname string) error

	// Authenticate is called after AUTH
	Authenticate(identity, username, password string) error

	// Sender is called after MAIL FROM
	Sender(address string) error

	// Recipient is called after RCPT TO
	Recipient(address string) error

	// Message is called after DATA. The reader returns the message data
	// after dot unstuffing. The final ".\r\n" is not included in the data.
	// When the complete message is consumed io.EOF is returned. It's not
	// required to consume all data. Any remaining data will be discarded
	// after Message() returns and the reader will become invalid.
	Message(reader io.Reader) error
}

type session struct {
	server    *Server
	conn      *conn
	handler   Handler
	tls       bool // using tls
	hasSender bool // mail given
	hasRcpt   bool // rcpt given
}

// ServeSMTP should be called by the application for each incoming connection.
//
// The application provides a new instance of the Handler interface that
// can be used to process command parameters and read the message data.
//
// The application should close the connection after ServeSMTP returns.
func (s *Server) ServeSMTP(conn net.Conn, handler Handler) error {

	sess := &session{
		server: s,
		conn:   newConn(conn),
		//state: state_init,
		handler: handler,
	}

	/*
		    if Debug {
				defer func() {
					log.Printf("Close connection from %s", source)
					sess.conn.Close()
				}()
			} else {
				defer sess.conn.Close()
			}
	*/

	err := handler.Connect(conn.RemoteAddr().String())
	if err != nil {
		sess.conn.ErrorReply(err)
		return nil
	}
	sess.conn.Reply("220 %s ESMTP %s", s.hostname(), time.Now().Format(time.RFC1123Z))

	for {
		line, err := sess.conn.ReadLine()
		if err != nil {
			return err
		}
		// trim space by adjusting slice
		line = strings.TrimSpace(line)
		// split at first space
		var verb, params string
		i := strings.IndexByte(line, ' ')
		if i != -1 {
			verb = strings.ToUpper(line[0:i])
			params = strings.TrimSpace(line[i+1:])
		} else {
			verb = strings.ToUpper(line)
		}

		switch verb {
		case "HELO":
			sess.helo(params)
		case "EHLO":
			sess.ehlo(params)
		case "STARTTLS":
			sess.starttls(conn)
		case "AUTH":
			sess.auth(params)
		case "MAIL":
			sess.mail(params)
		case "RCPT":
			sess.rcpt(params)
		case "DATA":
			sess.data()
		case "RSET":
			sess.rset()
		case "QUIT":
			sess.conn.Reply("221 %s closing connection", s.hostname())
			return nil // disconnect
		default:
			sess.conn.Reply("500 unrecognized command: %+q", verb)
		}
	}
}

func (s *session) helo(params string) {
	if params == "" {
		s.conn.Reply("501 Syntax: HELO hostname")
		return
	}
	// save client hostname
	err := s.handler.Hello(params)
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}
	s.conn.Reply("250 %s", s.server.hostname())
}

func (s *session) ehlo(params string) {
	if params == "" {
		s.conn.Reply("501 Syntax: EHLO hostname")
		return
	}
	// save client hostname
	err := s.handler.Hello(params)
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}

	lines := []string{s.server.Hostname}
	if s.server.TLSConfig != nil && s.tls == false {
		lines = append(lines, "STARTTLS")
	}
	if s.tls {
		lines = append(lines, "AUTH PLAIN LOGIN")
	}
	if s.server.Pipelining {
		lines = append(lines, "PIPELINING")
	}
	// 8BITMIME
	// SIZE
	s.conn.MultiLineReply(250, lines...)
}

func (s *session) starttls(conn net.Conn) {
	if s.server.TLSConfig == nil {
		s.conn.Reply("500 STARTTLS not supported")
		return
	}
	// check if already running tls
	if s.tls {
		s.conn.Reply("500 TLS already in use")
		return
	}
	s.conn.Reply("220 2.0.0 ready to start TLS")
	tlsConn := tls.Server(conn, s.server.TLSConfig)
	/*
		err := tlsConn.Handshake()
		if err != nil {
			s.conn.Reply("550 %s", err.Error())
			return
		}
		state := tlsConn.ConnectionState()
		fmt.Printf("server %t %x %x\n", state.HandshakeComplete, state.Version, state.CipherSuite)
	*/
	s.conn = newConn(tlsConn)

	s.tls = true
}

func (s *session) auth(params string) {
	if s.tls == false {
		s.conn.Reply("502 AUTH not allowed, use STARTTLS first")
		return
	}
	fields := strings.Fields(params)
	mechanism := strings.ToUpper(fields[0])
	var identity, username, password string
	switch mechanism {
	case "PLAIN":
		var auth string
		if len(fields) < 2 {
			s.conn.Reply("334 Give me your credentials")
			line, err := s.conn.ReadLine()
			if err != nil {
				return // no sense to reply, disconnect?
			}
			auth = line
		} else {
			auth = fields[1]
		}
		data, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			s.conn.Reply("502 Couldn't decode your credentials")
			return
		}
		// The client sends the authorization identity (identity to login as),
		// followed by a US-ASCII NULL character, followed by the authentication
		// identity (identity whose password will be used), followed by a US-ASCII
		// NULL character, followed by the clear-text password. The client may
		// leave the authorization identity empty to indicate that it is the same
		// as the authentication identity.
		parts := bytes.Split(data, []byte{0})
		if len(parts) != 3 {
			s.conn.Reply("502 Couldn't decode your credentials")
			return
		}
		identity = string(parts[0])
		username = string(parts[1])
		password = string(parts[2])
	case "LOGIN":
		s.conn.Reply("334 VXNlcm5hbWU6") // "Username:" in Base64
		line, err := s.conn.ReadLine()
		if err != nil {
			return // no sense to reply?
		}
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			s.conn.Reply("502 Couldn't decode your credentials")
			return
		}
		username = string(data)
		s.conn.Reply("334 UGFzc3dvcmQ6") // "Password:" in Base64
		line, err = s.conn.ReadLine()
		if err != nil {
			return // no sense to reply?
		}
		data, err = base64.StdEncoding.DecodeString(line)
		if err != nil {
			s.conn.Reply("502 Couldn't decode your credentials")
			return
		}
		password = string(data)
	default:
		s.conn.Reply("502 Unknown authentication mechanism")
	}
	err := s.handler.Authenticate(identity, username, password)
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}
	s.conn.Reply("235 OK, you are now authenticated")
}

func (s *session) mail(params string) {

	if s.hasSender {
		s.conn.Reply("503 Sender already given")
		return
	}

	if len(params) < 5 || strings.EqualFold(params[0:5], "FROM:") == false {
		s.conn.Reply("501 Syntax: MAIL FROM:<address>")
		return
	}

	addr := address(params[5:]) // could be empty for remote bounces
	// BODY=, SIZE=, AUTH=, ENVID=, RET=
	err := s.handler.Sender(addr)
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}
	s.hasSender = true
	s.conn.Reply("250 OK")
}

func (s *session) rcpt(params string) {
	if s.hasSender == false {
		s.conn.Reply("503 RCPT TO without MAIL FROM") // No sender given
		return
	}

	if len(params) < 3 || strings.EqualFold(params[0:3], "TO:") == false {
		s.conn.Reply("501 5.5.4 Syntax: RCPT TO:<address>")
		return
	}

	// TODO: return 452 too many recipients when too many recipients (RFC 5321 section 4.5.3.1.10)
	addr := address(params[3:])
	// ORCPT=, NOTIFY=
	err := s.handler.Recipient(addr)
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}
	s.hasRcpt = true
	s.conn.Reply("250 OK")
}

func (s *session) data() {
	if s.hasRcpt == false {
		s.conn.Reply("503 DATA without RCPT TO")
		return
	}
	s.conn.Reply("354 End data with <CR><LF>.<CR><LF>")
	reader := &dotReader{
		r: s.conn.r.R,
	}
	err := s.handler.Message(reader)
	io.Copy(ioutil.Discard, reader) // discard any remaining data
	if err != nil {
		s.conn.ErrorReply(err)
		return
	}
	s.hasSender = false
	s.hasRcpt = false
	s.conn.Reply("250 OK")
}

func (s *session) rset() {
	s.hasSender = false
	s.hasRcpt = false
	s.conn.Reply("250 OK")
}

var reAddress = regexp.MustCompile(` ?<?([^>\s]+)`)

func address(param string) (addr string) {
	if m := reAddress.FindStringSubmatch(param); m != nil {
		addr = m[1]
	}
	return
}
