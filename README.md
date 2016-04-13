# smtpd

BRANCH WITH ATTEMPT TO USE net.textproto

Library for implementing simple SMTP servers. It's responsible for handling the SMTP server side protocol, nothing more, nothing less. Callbacks can be specified to act on, or reject parameters at different stages of session initialization or message transaction.

## Testing

For testing authentication a TLS connection is used. Create a self-signed certificate before running the tests:

	mkdir test
	openssl genrsa 2048 > test/key.pem
    openssl req -x509 -new -key key.pem > test/cert.pem
    