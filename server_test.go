package smtpd

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"testing"
)

var testMessage = []byte(`From: sender@example.com
To: recipient@example.com
Subject: test

This is a test.
`)

type testHandler struct{}

func (h testHandler) Connect(source string) error { return nil }

func (h testHandler) Hello(hostname string) error { return nil }

// Authenticate is called after AUTH
func (h testHandler) Authenticate(identity, username, password string) error {
	if username == "user@example.com" && password == "password" {
		return nil
	}
	return fmt.Errorf("550 Unauthorized")
}

// Sender is called after MAIL FROM
func (h testHandler) Sender(address string) error { return nil }

// Recipient is called after RCPT TO
func (h testHandler) Recipient(address string) error { return nil }

// Message is called after DATA
func (h testHandler) Message(reader io.Reader) error { return nil }

func TestSendMail(t *testing.T) {

	Debug = true

	runServer(t, &Server{}, testHandler{})

	err := sendMail("127.0.0.1:10025", nil, "sender@example.com", []string{"recipient@example.com"}, testMessage)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
}

func TestSendMailWithAuth(t *testing.T) {

	Debug = true

	// openssl genrsa 2048 > test/key.pem
	// openssl req -x509 -new -key key.pem > test/cert.pem
	//
	// Country Name (2 letter code) [AU]:.
	// State or Province Name (full name) [Some-State]:.
	// Locality Name (eg, city) []:
	// Organization Name (eg, company) [Internet Widgits Pty Ltd]:.
	// Organizational Unit Name (eg, section) []:
	// Common Name (e.g. server FQDN or YOUR name) []:127.0.0.1
	// Email Address []:

	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//ClientAuth:   tls.VerifyClientCertIfGiven,
		//ServerName:   "localhost",
	}

	server := &Server{
		TLSConfig: tlsConfig,
	}

	runServer(t, server, testHandler{})

	auth := smtp.PlainAuth("", "user@example.com", "password", "127.0.0.1")
	err = sendMail("127.0.0.1:10025", auth, "sender@example.com", []string{"recipient@example.com"}, testMessage)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
}

func runServer(t *testing.T, server *Server, handler Handler) {

	listener, err := net.Listen("tcp", "127.0.0.1:10025")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}

	go func() {
		defer listener.Close()

		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("%s", err.Error())
		}

		err = server.ServeSMTP(conn, handler)
		if err != nil {
			t.Fatalf("%s", err.Error())
		}
	}()
	// close listener to abort
}

// sendMail does the same as smtp.SendMail, but without verifying TLS certificate
func sendMail(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()

	err = c.Hello("localhost")
	if err != nil {
		return err
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		if err = c.StartTLS(config); err != nil {
			return err
		}
		//if state, ok := c.TLSConnectionState(); ok {
		//	log.Printf("client %t %x %x", state.HandshakeComplete, state.Version, state.CipherSuite)
		//}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err = c.Auth(a); err != nil {
				return err
			}
		}
	}
	if err = c.Mail(from); err != nil {
		return err
	}
	for _, addr := range to {
		if err = c.Rcpt(addr); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	c.Quit()
	// => tls: received record with version 3231 when expecting version 303
	return nil
}
