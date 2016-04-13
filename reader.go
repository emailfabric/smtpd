package smtpd

import (
	"bufio"
	"io"
)

// textproto.Reader#DotReader() rewrites standard CRLF line endings to LF which
// causes issues when mails are signed or forwarded
// this replacement preserves line endings and also implements io.WriterTo which 
// is more efficient when io.Copy is used on the reader

const (
	stateBeginLine = iota // beginning of line; initial state; must be zero
	stateDot              // read . at beginning of line
	stateDotCR            // read .\r at beginning of line
	stateData             // reading data in middle of line
	stateEOF              // reached .\r\n end marker line
)

type dotReader struct {
	r     *bufio.Reader
	state int
}

// Read chunk of message data.
// If the line is composed of a single period, it is treated as the end of 
// mail indicator and io.EOF is returned. If the first character is a period 
// and there are other characters on the line, the first character is deleted.
func (d *dotReader) Read(b []byte) (n int, err error) {
	br := d.r
	state := d.state
	for n < len(b) && state != stateEOF {
		var c byte
		c, err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}

		switch state {
		case stateBeginLine:
			if c == '.' {
				state = stateDot
				continue  // discard dot
			}
			if c != '\n' {
    			state = stateData
			}
		case stateDot:
			if c == '\r' {
				state = stateDotCR
				continue
			}
			if c == '\n' {
				state = stateEOF  // exit loop
				continue
			}
			state = stateData
		case stateDotCR:
			if c == '\n' {
				state = stateEOF  // exit loop
				continue
			}
			// .CR not followed by LF, should not occur
            c = '\r'
			br.UnreadByte()
			state = stateData
		case stateData:
			if c == '\n' {
				state = stateBeginLine
			}
		}

		b[n] = c
		n++
	}
	if err == nil && state == stateEOF {
		err = io.EOF
	}
	d.state = state
	return
}

// WriteTo implements WriterTo which can be used in io.Copy.
// It is more efficient than Read() because it loops on lines instead of bytes.
func (d *dotReader) WriteTo(w io.Writer) (n int64, err error) {
	if d.state == stateEOF {
		return 0, io.EOF
	}
	for {
		line, err := d.r.ReadSlice('\n')
		if err != nil {
    	    // ErrBufferFull should not occur as lines must be 1000 bytes or less
    	    // a partial line may be returned after error (often io.EOF)
			if line != nil {
    			written, _ := w.Write(line)
        		n += int64(written)
			}
		    if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		// line starts with dot?
		if len(line) >= 2 && line[0] == '.' {
		    // followed by CRLF or LF?
			if line[1] == '\r' || line[1] == '\n' {
				d.state = stateEOF
        		return 0, io.EOF  // discard .CRLF
			}
			// followed by other character, remove dot
			line = line[1:]
		}
		// copy line including (CR)LF
		written, err := w.Write(line)
		n += int64(written)
		if err != nil {
			return n, err
		}
	}
}
