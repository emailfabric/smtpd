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
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// Server is an SMTP server.
// An uninitialized Server is valid, but only useful as blackhole.
type Server struct {
	// Hostname to use in responses
	Hostname string

	// Set to enable STARTTLS
	// must include at least one certificate or else set GetCertificate
	TLSConfig *tls.Config
	
	// Set to enable PIPELINING
	Pipelining bool

	// Hooks called during session initialization
	ConnHook SessionHook
	EhloHook SessionHook
	AuthHook SessionHook
	
	// Hooks called during message transactions
	MailHook TransactionHook
	RcptHook TransactionHook
	DataHook TransactionHook
}

// SessionHook functions are called during session initiation steps.
type SessionHook func (*SessionInfo) (ok bool, err error)

// SessionInfo captures information related to the SMTP session.
type SessionInfo struct {
	// Source is the remote address taken from the connection
	// Available in ConnHook, EhloHook and AuthHook
	Source string

	// Domain is the client domain taken from EHLO or HELO
	// Available in EhloHook and AuthHook
	Domain string
	
	// TLS is in use
	// Available in AuthHook
    TLS bool
    
	// Username, password used for authentication
	// Available in AuthHook
	Username, Password string
	
	//RelayAllowed bool
}

// TransactionHook functions are called during SMTP transaction steps.
type TransactionHook func (*TransactionInfo) (ok bool, err error)

// TransactionInfo captures relevant information related to an SMTP transaction.
type TransactionInfo struct {
    // Session provides access to session information 
    *SessionInfo

	// Sender is the reverse-path address taken from MAIL FROM
	// Available in MailHook, RcptHook and DataHook
	Sender string

	// Recipients are the forward-path addresses taken from RCPT TO
	// Available in RcptHook and DataHook
	Recipients []string

	// Data is a reader that can be used to read the message data.
	// Leading dots are unstuffed by the reader.
	// The reader returns io.EOF error at the end of the data.
	// Available in DataHook
	Data io.Reader
}

// Debug can be set to true to print SMTP trace to the standard log facility.
var Debug = false

// DefaultHostname is used in banner greeting when Server#hostname is empty.
var DefaultHostname, _ = os.Hostname()

//func (srv *Server) Serve(l net.Listener) error

// ServeSMTP is called by the application for each incoming connection
// The application provides an instance of the Session interface that
// can be used to validate and store command parameters
func (s *Server) ServeSMTP(conn net.Conn) error {

	if s.Hostname == "" {
		s.Hostname = DefaultHostname
	}
	
	// save remote address
	source := conn.RemoteAddr().String()

	if Debug {
		defer func() {
			log.Printf("Close connection from %s", source)
			conn.Close()
		}()
	} else {
		defer conn.Close()
	}

	h := newConn(conn)

    sessionInfo := &SessionInfo{
        Source: source,
    }
	if s.ConnHook != nil {
		ok, err := s.ConnHook(sessionInfo)
		if err != nil {
			h.Reply(ErrorReply(err).String())
			return nil
		}
		if !ok {
			h.Reply("554 No SMTP service for you [%s] here", source)
			return nil
		}
	}
	h.Reply("220 %s ESMTP %s", s.Hostname, time.Now().Format(time.RFC1123Z))

	session := &session{
		server: s,
		conn:   h,
		//state: state_init,
		sessionInfo: sessionInfo,
	}
	for {
		verb, params, err := session.conn.ReadCmd()
		if err != nil {
			return err
		}
		switch verb {
		case "HELO":
			session.helo(params)
		case "EHLO":
			session.ehlo(params)
		case "STARTTLS":
			session.starttls(conn)
		case "AUTH":
			session.auth(params)
		case "MAIL":
			session.mail(params)
		case "RCPT":
			session.rcpt(params)
		case "DATA":
			session.data()
		case "RSET":
			session.rset()
		case "QUIT":
			h.Reply("221 %s closing connection", s.Hostname)
			return nil // disconnect
		default:
			h.Reply("500 unrecognized command: %+q", verb)
		}
	}
}

type session struct {
	server *Server
	*conn
	//state state
	sessionInfo *SessionInfo
	transactionInfo *TransactionInfo
}

func (s *session) helo(params string) {
	if params == "" {
		s.Reply("501 Syntax: HELO hostname")
		return
	}
	// save client hostname
	s.sessionInfo.Domain = params
	s.Reply("250 %s", s.server.Hostname)
}

func (s *session) ehlo(params string) {
	if params == "" {
		s.Reply("501 Syntax: EHLO hostname")
		return
	}
	// save client hostname
	s.sessionInfo.Domain = params
	
	lines := []string{s.server.Hostname}
	if s.server.TLSConfig != nil && s.sessionInfo.TLS == false {
		lines = append(lines, "STARTTLS")
	}
	if s.server.AuthHook != nil && s.sessionInfo.TLS == true {
		lines = append(lines, "AUTH PLAIN LOGIN")
	}
	if s.server.Pipelining {
    	lines = append(lines, "PIPELINING")
	}
	// 8BITMIME
	// SIZE
	s.MultiLineReply(250, lines...)
}

func (s *session) starttls(conn net.Conn) {
	if s.server.TLSConfig == nil {
		s.Reply("500 STARTTLS not supported")
		return
	}
	// TODO: check if already running tls
	s.Reply("220 2.0.0 ready to start TLS")
	tlsConn := tls.Server(conn, s.server.TLSConfig)
	/*
	err := tlsConn.Handshake()
	if err != nil {
		s.Reply("550 %s", err.Error())
		return
	}
	state := tlsConn.ConnectionState()
	fmt.Printf("server %t %x %x\n", state.HandshakeComplete, state.Version, state.CipherSuite)
    */
	s.conn = newConn(tlsConn)

	s.sessionInfo.TLS = true
}

func (s *session) auth(params string) {
	if s.server.AuthHook == nil {
		s.Reply("502 AUTH not supported")
		return
	}
	if s.sessionInfo.Username != "" {
		s.Reply("503 AUTH already issued")
		return
	}
	fields := strings.Fields(params)
	mechanism := strings.ToUpper(fields[0])
	switch mechanism {
	case "PLAIN":
		var auth string
		if len(fields) < 2 {
			s.Reply("334 Give me your credentials")
			line, err := s.ReadLine()
			if err != nil {
				return // no sense to reply, disconnect?
			}
			auth = line
		} else {
			auth = fields[1]
		}
		data, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			s.Reply("502 Couldn't decode your credentials")
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
			s.Reply("502 Couldn't decode your credentials")
			return
		}
		//identity = string(parts[0])
		s.sessionInfo.Username = string(parts[1])
		s.sessionInfo.Password = string(parts[2])
	case "LOGIN":
		s.Reply("334 VXNlcm5hbWU6") // "Username:" in Base64
		line, err := s.ReadLine()
		if err != nil {
			return // no sense to reply?
		}
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			s.Reply("502 Couldn't decode your credentials")
			return
		}
		s.sessionInfo.Username = string(data)
		s.Reply("334 UGFzc3dvcmQ6") // "Password:" in Base64
		line, err = s.ReadLine()
		if err != nil {
			return // no sense to reply?
		}
		data, err = base64.StdEncoding.DecodeString(line)
		if err != nil {
			s.Reply("502 Couldn't decode your credentials")
			return
		}
		s.sessionInfo.Password = string(data)
	default:
		s.Reply("502 Unknown authentication mechanism")
	}
	ok, err := s.server.AuthHook(s.sessionInfo)
	if err != nil {
		s.Reply(ErrorReply(err).String())
		return
	}
	if !ok {
		s.Reply("535 Invalid credentials")
		return
	}
	s.Reply("235 OK, you are now authenticated")
}

func (s *session) mail(params string) {
    
	if s.transactionInfo != nil {
		s.Reply("503 Sender already given")
		return
	}

	if len(params) < 5 || strings.EqualFold(params[0:5], "FROM:") == false {
		s.Reply("501 Syntax: MAIL FROM:<address>")
		return
	}
	
	s.transactionInfo = &TransactionInfo{
	    SessionInfo: s.sessionInfo,
	    Sender: address(params[5:]),  // could be empty for remote bounces
	    //Recipients: make([]string, 0),
	}

	if s.server.MailHook != nil {
		ok, err := s.server.MailHook(s.transactionInfo)
		if err != nil {
			s.Reply(ErrorReply(err).String())
			return
		}
		if !ok {
			// ?relay access denied, syntax error, ...
			s.Reply("550 Invalid sender: %q", s.transactionInfo.Sender)
		    // remove message context
		    s.transactionInfo = nil
			return
		}
	}
    
	// BODY=, AUTH=, ENVID=, RET=
	s.Reply("250 OK")
}

func (s *session) rcpt(params string) {
	if s.transactionInfo == nil {
		s.Reply("503 RCPT TO without MAIL FROM") // No sender given
		return
	}

	if len(params) < 3 || strings.EqualFold(params[0:3], "TO:") == false {
		s.Reply("501 5.5.4 Syntax: RCPT TO:<address>")
		return
	}

	// TODO: return 452 too many recipients when too many recipients (RFC 5321 section 4.5.3.1.10)
	addr := address(params[3:])
	s.transactionInfo.Recipients = append(s.transactionInfo.Recipients, addr)
	if s.server.RcptHook != nil {
		ok, err := s.server.RcptHook(s.transactionInfo)
		if err != nil {
			s.Reply(ErrorReply(err).String())
		    // remove last recipient from context
		    s.transactionInfo.Recipients = s.transactionInfo.Recipients[0:len(s.transactionInfo.Recipients)-1]
			return
		}
		if !ok {
			// ?relay access denied, syntax error, ...
			s.Reply("550 Invalid recipient: %q", addr)
		    // remove last recipient from context
		    s.transactionInfo.Recipients = s.transactionInfo.Recipients[0:len(s.transactionInfo.Recipients)-1]
			return
		}
	}

	// ORCPT=, NOTIFY=
	s.Reply("250 OK")
}

func (s *session) data() {
	// read data
	//if s.state != state_rcpt {
	if len(s.transactionInfo.Recipients) == 0 {
		s.Reply("503 DATA without RCPT TO")
		return
	}
	s.Reply("354 End data with <CR><LF>.<CR><LF>")
	//data := h.r.DotReader()
	s.transactionInfo.Data = &dataReader{Reader: s.conn.r}
	if s.server.DataHook != nil {
		// call receive handler
		ok, err := s.server.DataHook(s.transactionInfo)
		if err != nil {
        	io.Copy(ioutil.Discard, s.transactionInfo.Data)  // discard remaining data
			s.Reply(ErrorReply(err).String())
			return
		}
		if !ok {
        	io.Copy(ioutil.Discard, s.transactionInfo.Data)  // discard remaining data
			s.Reply("550 Message rejected")
			return
		}
	}
	io.Copy(ioutil.Discard, s.transactionInfo.Data)  // discard remaining data
	s.Reply("250 OK")
	s.transactionInfo = nil
}

func (s *session) rset() {
	s.transactionInfo = nil
	s.Reply("250 OK")
}

var reAddress = regexp.MustCompile(` ?<?([^>\s]+)`)

func address(param string) (addr string) {
	if m := reAddress.FindStringSubmatch(param); m != nil {
		addr = m[1]
	}
	return
}
