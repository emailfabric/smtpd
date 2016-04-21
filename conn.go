package smtpd

import (
	"bufio"
	//"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"strings"
	"unicode"
)

// conn represents a connection to the smtp server
type conn struct {
	r *textproto.Reader
	//r *bufio.Reader
	w *bufio.Writer
}

func newConn(c net.Conn) *conn {
	var r io.Reader
	var w io.Writer
	if Debug {
		log.Printf("Connection from %s to %s", c.RemoteAddr(), c.LocalAddr())
		r = io.TeeReader(c, new(logReadWriter))
		w = io.MultiWriter(c, new(logWriter))
	} else {
		r = c
		w = c
	}
	//reader := bufio.NewReader(r)
	reader := textproto.NewReader(bufio.NewReader(r))
	writer := bufio.NewWriter(w)
	return &conn{reader, writer}
}

// ReadLine reads a single line from c, without the final \n or \r\n.
func (c *conn) ReadLine() (string, error) {
	//line, err := h.readLineSlice()
	//return string(line), err
	return c.r.ReadLine()
}

// DotReader returns a new io.Reader. The Reader's Read method
// rewrites the "\r\n" line endings into the simpler "\n",
// removes leading dot escapes if present, and stops with error io.EOF
// after consuming (and discarding) the end-of-sequence line.
func (c *conn) DotReader() io.Reader {
	//&dataReader{Reader: s.conn.r}
	return c.r.DotReader()
}

/*
// ReadCmd reads next line, trims whitespace, and splits it at first space
func (h *conn) ReadCmd() (verb string, params string, err error) {
	line, err := h.readLineSlice()
	if err != nil {
		return
	}
	// trim space by adjusting slice
	line = bytes.TrimSpace(line)
	// find first space delimiter
	i := bytes.IndexByte(line, ' ')
	if i == -1 {
		// copy slice to string in uppercase
		verb = strings.ToUpper(string(line))
		return
	}
	verb = strings.ToUpper(string(line[0:i]))
	params = string(bytes.TrimSpace(line[i+1:]))
	return
}

// ReadLine returns a line slice, not including end-of-line bytes
// make sure to copy the slice before calling ReadLine again
func (h *conn) readLineSlice() (line []byte, err error) {
	line, more, err := h.r.ReadLine()
	if err != nil {
		return
	}
	if more {
		// this should not occur, the buffer is much larger than the
		// longest allowed smtp command (512 octets including CRLF)
		// return an error breaking the connection
		err = fmt.Errorf("Input caused buffer overrun")
		return
	}
	return
}
*/

var crlf = []byte{'\r', '\n'}

// Reply writes the formatted output followed by \r\n.
func (c *conn) Reply(format string, args ...interface{}) error {
	fmt.Fprintf(c.w, format, args...)
	c.w.Write(crlf)
	// TODO: reset write deadline and read deadline
	return c.w.Flush()
}

func (c *conn) ErrorReply(err error) error {
	msg := err.Error()
	// starts with 3-digits?
	if strings.IndexFunc(msg, func(r rune) bool {
		return unicode.IsNumber(r) == false
	}) == 3 {
		fmt.Fprintf(c.w, "%s\r\n", msg)
	} else {
		fmt.Fprintf(c.w, "451 Requested action aborted: %s\r\n", msg)
	}
	return c.w.Flush()
}

func (c *conn) MultiLineReply(status int, args ...string) error {
	i := 0
	for ; i < len(args)-1; i++ {
		fmt.Fprintf(c.w, "%d-%s\r\n", status, args[i])
	}
	fmt.Fprintf(c.w, "%d %s\r\n", status, args[i])
	return c.w.Flush()
}

// logReadWriter writes each read line preceded with "-> "
type logReadWriter struct {
	total int
}

func (w *logReadWriter) Write(p []byte) (n int, err error) {
	// split on intermediate CRLFs (not trailing CRLF)
	lines := strings.Split(strings.TrimSuffix(string(p), "\r\n"), "\r\n")
	for _, l := range lines {
		log.Printf("-> %s", l)
	}
	w.total += len(p)
	return len(p), nil
}

// logWriter writes each line preceded with "<- "
type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	lines := strings.Split(strings.TrimSuffix(string(p), "\r\n"), "\r\n")
	for _, l := range lines {
		log.Printf("<- %s", l)
	}
	return len(p), nil
}
