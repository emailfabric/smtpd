package smtpd

import (
	"bufio"
	"io"
)

// note that textproto.Reader#DotReader() rewrites the "\r\n" line endings into the simpler "\n"

type dataReader struct {
	*bufio.Reader
	done    bool
	unstuff bool // true to enable dot unstuffing
}

// Read implements io.Reader, reads one line at a time, buffer should allow for 1000 bytes
func (r *dataReader) Read(p []byte) (n int, err error) {
	if r.done {
		return 0, io.EOF
	}
	line, err := r.ReadSlice('\n') // ReadLine()?
	if err != nil {
		return
	}
	// ? optional sanitize line endings (LF -> CRLF)
	if len(line) >= 2 && line[0] == '.' {
		// stop after line with .CRLF or .LF
		if line[1] == '\r' || line[1] == '\n' {
			r.done = true
			return 0, io.EOF
		}
		// optional unescape leading dot (.. -> .)
		if line[1] == '.' && r.unstuff {
			line = line[1:]
		}
	}
	// Copy line. Bytes returned from ReadSlice are overwritten at the next read.
	n = copy(p, line)
	if len(line) > n {
		return n, io.ErrShortBuffer
	}
	return
}

// WriteTo implements WriterTo which is used in io.Copy
func (r *dataReader) WriteTo(w io.Writer) (n int64, err error) {
	if r.done {
		return 0, io.EOF
	}
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return n, err
		}
		if len(line) >= 2 && line[0] == '.' {
			if line[1] == '\r' || line[1] == '\n' {
				r.done = true
				break
			}
			if line[1] == '.' && r.unstuff {
				line = line[1:]
			}
		}
		written, err := w.Write(line)
		n += int64(written)
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Flush makes sure that the complete message is read
func (r *dataReader) Flush() {
	if r.done {
		return
	}
	line, err := r.ReadSlice('\n')
	if err != nil {
		return
	}
	if len(line) >= 2 && line[0] == '.' {
		if line[1] == '\r' || line[1] == '\n' {
			r.done = true
			return
		}
	}
}
