package parser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/textproto"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Protocol string

const (
	HTTP   Protocol = "HTTP"
	ADB    Protocol = "ADB"
	Telnet Protocol = "TELNET"
	Raw    Protocol = "RAW"
)

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
	[]byte("TRACE "), []byte("PROPFIND "), []byte("M-SEARCH "), []byte("NOTIFY "),
	[]byte("SUBSCRIBE "),
}

var adbCommands = map[string]bool{
	"CNXN": true, "AUTH": true, "OPEN": true, "OKAY": true,
	"CLSE": true, "WRTE": true, "SYNC": true,
}

func Detect(b []byte) Protocol {
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			return HTTP
		}
	}
	if len(b) >= 4 && adbCommands[string(b[:4])] {
		if len(b) < adbHeaderLen || validADBMagic(b) {
			return ADB
		}
	}
	if len(b) > 0 && b[0] == iac {
		return Telnet
	}
	return Raw
}

type Status int

const (
	NeedMore Status = iota
	Done
	Invalid
)

type HTTPRequest struct {
	Method        string
	Target        string
	Version       string
	Headers       map[string]string
	HeaderLines   []string
	UserAgent     string
	ContentLength int
	Body          []byte
	KeepAlive     bool
}

func ParseHTTPRequest(buf []byte, final bool) (*HTTPRequest, int, Status) {
	hdrEnd, sepLen := indexHeaderEnd(buf)
	if hdrEnd < 0 {
		if final && len(buf) > 0 {

			hdrEnd, sepLen = len(buf), 0
		} else {
			return nil, 0, NeedMore
		}
	}
	head := string(buf[:hdrEnd])
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 || !validMethod(parts[0]) {

		return nil, 0, Invalid
	}
	req := &HTTPRequest{
		Method:  parts[0],
		Target:  parts[1],
		Version: "HTTP/1.0",
		Headers: make(map[string]string),
	}
	if len(parts) >= 3 {
		req.Version = parts[2]
	}
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		req.HeaderLines = append(req.HeaderLines, ln)
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		k = textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(k))
		if _, dup := req.Headers[k]; !dup {
			req.Headers[k] = strings.TrimSpace(v)
		}
	}
	req.UserAgent = req.Headers["User-Agent"]
	conn := strings.ToLower(req.Headers["Connection"])
	req.KeepAlive = strings.Contains(conn, "keep-alive") ||
		(req.Version == "HTTP/1.1" && !strings.Contains(conn, "close"))

	bodyStart := hdrEnd + sepLen
	rest := buf[bodyStart:]

	if cl := req.Headers["Content-Length"]; cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || n < 0 {
			n = 0
		}
		req.ContentLength = n
		if len(rest) < n {
			if !final {
				return nil, 0, NeedMore
			}
			n = len(rest)
		}
		req.Body = rest[:n]
		return req, bodyStart + n, Done
	}
	if strings.Contains(strings.ToLower(req.Headers["Transfer-Encoding"]), "chunked") {
		if !final && !bytes.Contains(rest, []byte("0\r\n\r\n")) && !bytes.Contains(rest, []byte("0\n\n")) {
			return nil, 0, NeedMore
		}
		req.Body = rest
		return req, len(buf), Done
	}
	return req, bodyStart, Done
}

func validMethod(m string) bool {
	if len(m) < 3 || len(m) > 16 {
		return false
	}
	for i := 0; i < len(m); i++ {
		if (m[i] < 'A' || m[i] > 'Z') && m[i] != '-' {
			return false
		}
	}
	return true
}

func indexHeaderEnd(b []byte) (idx, sepLen int) {
	crlf := bytes.Index(b, []byte("\r\n\r\n"))
	lf := bytes.Index(b, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return crlf, 4
	case lf >= 0:
		return lf, 2
	}
	return -1, 0
}

const adbHeaderLen = 24

var ErrADBFraming = errors.New("adb: invalid framing")

type ADBMessage struct {
	Command string
	Arg0    uint32
	Arg1    uint32
	Payload []byte
}

func validADBMagic(b []byte) bool {
	cmd := binary.LittleEndian.Uint32(b[0:4])
	magic := binary.LittleEndian.Uint32(b[20:24])
	return magic == ^cmd
}

func ParseADB(buf []byte, maxPayload int) ([]ADBMessage, int, error) {
	var msgs []ADBMessage
	off := 0
	for len(buf)-off >= adbHeaderLen {
		h := buf[off : off+adbHeaderLen]
		if !adbCommands[string(h[:4])] || !validADBMagic(h) {
			return msgs, off, ErrADBFraming
		}
		n := int(binary.LittleEndian.Uint32(h[12:16]))
		if n < 0 || n > maxPayload {
			return msgs, off, ErrADBFraming
		}
		if len(buf)-off < adbHeaderLen+n {
			break
		}
		msgs = append(msgs, ADBMessage{
			Command: string(h[:4]),
			Arg0:    binary.LittleEndian.Uint32(h[4:8]),
			Arg1:    binary.LittleEndian.Uint32(h[8:12]),
			Payload: append([]byte(nil), buf[off+adbHeaderLen:off+adbHeaderLen+n]...),
		})
		off += adbHeaderLen + n
	}
	return msgs, off, nil
}

func BuildADB(cmd string, arg0, arg1 uint32, payload []byte) []byte {
	out := make([]byte, adbHeaderLen, adbHeaderLen+len(payload))
	copy(out[0:4], cmd)
	binary.LittleEndian.PutUint32(out[4:8], arg0)
	binary.LittleEndian.PutUint32(out[8:12], arg1)
	binary.LittleEndian.PutUint32(out[12:16], uint32(len(payload)))
	var sum uint32
	for _, c := range payload {
		sum += uint32(c)
	}
	binary.LittleEndian.PutUint32(out[16:20], sum)
	binary.LittleEndian.PutUint32(out[20:24], ^binary.LittleEndian.Uint32(out[0:4]))
	return append(out, payload...)
}

const (
	iac  = 255
	sb   = 250
	se   = 240
	will = 251
	dont = 254
)

var (
	TelnetNegotiation = []byte{iac, will, 1, iac, will, 3}
)

func StripTelnet(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != iac {
			out = append(out, b[i])
			continue
		}
		if i+1 >= len(b) {
			break
		}
		switch c := b[i+1]; {
		case c == iac:
			out = append(out, iac)
			i++
		case c >= will && c <= dont:
			i += 2
		case c == sb:
			j := i + 2
			for j+1 < len(b) && !(b[j] == iac && b[j+1] == se) {
				j++
			}
			i = j + 1
		default:
			i++
		}
	}
	return out
}

func Sanitize(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		switch {
		case r == utf8.RuneError && size == 1:
			sb.WriteByte('.')
		case r == '\n' || r == '\r' || r == '\t':
			sb.WriteRune(r)
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
		b = b[size:]
	}
	return sb.String()
}

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
