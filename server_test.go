package smtpd

import (
	"crypto/tls"
	"net"
	"net/smtp"
	"testing"
)

var testMessage = []byte(`From: sender@example.com
To: recipient@example.com
Subject: test

This is a test.
`)

func TestSendMail(t *testing.T) {

	Debug = true

	runServer(t, &Server{})

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
    
	cert, err := tls.LoadX509KeyPair("test/cert.pem", "test/key.pem")
    if err != nil {
		t.Fatalf("%s", err.Error())
    }    
	
	tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
    	//ClientAuth:   tls.VerifyClientCertIfGiven,
    	//ServerName:   "localhost",
    }
	
	authHook := func (si *SessionInfo) (ok bool, err error) {
	    if si.Username == "user@example.com" && si.Password == "password" {
	        ok = true
	    }
	    return
	}

	server := &Server{
	    TLSConfig: tlsConfig,
	    AuthHook: authHook,
	}

	runServer(t, server)

    auth := smtp.PlainAuth("", "user@example.com", "password", "127.0.0.1")
    err = sendMail("127.0.0.1:10025", auth, "sender@example.com", []string{"recipient@example.com"}, testMessage)
    if err != nil {
		t.Fatalf("%s", err.Error())
    }    
}

func runServer(t *testing.T, server *Server) {

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

		err = server.ServeSMTP(conn)
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
	err = c.Quit()
	// tls: received record with version 3231 when expecting version 303
	return nil
}
