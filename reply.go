package smtpd

import (
	"strings"
	"unicode"
)

// Reply represents an SMTP server reply message.
type Reply string

// String implements the Stringer interface.
func (r Reply) String() string {
	return string(r)
}

// Error implements the error interface.
func (r Reply) Error() string {
	return string(r)
}

// ErrorReply converts an error to a Reply.
func ErrorReply(err error) Reply {
	msg := err.Error()
	// starts with 3-digit status?
	if hasStatus(msg) {
		return Reply(msg)
	} else {
		if isTemporary(err) {
			return Reply("400 " + msg)
		} else {
			return Reply("500 " + msg) // ?502
		}
	}
}

// hasStatus returns true if s starts with 3-digits
func hasStatus(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsNumber(r) == false
	}) == 3
}

// isTemporary checks if error implements Temporary() and if it returns true
func isTemporary(err error) bool {
	if te, ok := err.(temporary); ok {
		return te.Temporary()
	}
	return false
}

// temporary interface is implemented by some errors
type temporary interface {
	Temporary() bool
}

// http://blog.golang.org/error-handling-and-go
// http://dave.cheney.net/2014/12/24/inspecting-errors
