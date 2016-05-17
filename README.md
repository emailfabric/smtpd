# smtpd

[![](https://godoc.org/github.com/emailfabric/smtpd?status.svg)](http://godoc.org/github.com/emailfabric/smtpd)

Go library for implementing simple SMTP servers. It's responsible for handling the SMTP server side protocol, nothing more, nothing less. 

## Usage

Create a type that implements the smtpd.Handler interface.

Create a smtp.Server instance with specific options and a listener.

Pass each connection together with a handler instance to ServeSMTP().

## Testing

For testing authentication a TLS connection is used. Create a self-signed certificate before running the tests:

	mkdir testdata
	openssl genrsa 2048 > testdata/key.pem
    openssl req -x509 -new -key key.pem > testdata/cert.pem
