package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/profile"
	"github.com/generalregulator/botbait/internal/shell"
	"github.com/generalregulator/botbait/internal/vfs"
	"github.com/generalregulator/botbait/internal/webcam"
)

type Sink interface{ Submit(*model.Event) }

const (
	maxHTTPRequests = 3
	maxCommands     = 50
	maxCredentials  = 20
	maxCommandLen   = 4096
)

var errReadLimit = errors.New("session: read budget exhausted")

type Handler struct {
	cfg   *config.Config
	sink  Sink
	m     *metrics.Metrics
	store *payloadstore.Store
	start time.Time

	adbProf, telProf *profile.Profile
	adbBase, telBase *vfs.Base
	web              *webcam.Server
}

type Option func(*Handler)

func WithProfile(p *profile.Profile) Option { return func(h *Handler) { h.adbProf = p } }

func WithTelnetProfile(p *profile.Profile) Option { return func(h *Handler) { h.telProf = p } }

func WithWebSeed(seed string) Option { return func(h *Handler) { h.web = webcam.New(seed) } }

func WithStore(st *payloadstore.Store) Option { return func(h *Handler) { h.store = st } }

func New(cfg *config.Config, sink Sink, m *metrics.Metrics, opts ...Option) *Handler {
	h := &Handler{cfg: cfg, sink: sink, m: m, start: time.Now()}
	for _, o := range opts {
		o(h)
	}
	if h.adbProf == nil {
		h.adbProf, _ = profile.Load("android-tvbox", "default")
	}
	if h.telProf == nil {
		h.telProf = h.adbProf
	}
	if h.web == nil {
		h.web = webcam.New("")
	}
	h.adbBase = vfs.NewBase(h.adbProf)
	if h.telProf == h.adbProf {
		h.telBase = h.adbBase
	} else {
		h.telBase = vfs.NewBase(h.telProf)
	}
	return h
}

type sess struct {
	h      *Handler
	conn   net.Conn
	ev     *model.Event
	end    time.Time
	total  int
	budget int
	raw    []byte
	text   strings.Builder

	telnetMode bool
	fs         *vfs.FS
	sh         *shell.Shell
	drops      []model.DroppedFile
	pushed     map[string]bool
	pushGrant  bool
	pushRead   int64
	dstPort    int
}

func (h *Handler) Handle(_ context.Context, conn net.Conn, dstPort int) {
	defer conn.Close()
	start := time.Now()
	ev := &model.Event{
		ID:        newID(),
		Timestamp: start.UTC(),
		DstPort:   h.cfg.PublicPort(dstPort),
		Protocol:  string(parser.Raw),
		Action:    "Connect only (no data)",
	}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ev.SrcIP, ev.SrcPort = ta.IP.String(), ta.Port
	}
	s := &sess{h: h, conn: conn, ev: ev, end: start.Add(h.cfg.SessionTimeout), budget: h.cfg.MaxReadBytes, dstPort: dstPort}
	h.m.ActiveSessions.Add(1)
	defer h.m.ActiveSessions.Add(-1)

	s.run(dstPort)
	s.finishDrops()

	ev.SessionDurationMs = time.Since(start).Milliseconds()
	ev.BytesReceived = s.total
	switch ev.Protocol {
	case string(parser.HTTP), string(parser.Raw):

		ev.Text = parser.Sanitize(s.raw, h.cfg.MaxReadBytes)
	default:
		ev.Text = s.text.String()
	}
	ev.Dropped = s.drops
	h.sink.Submit(ev)
}

func (s *sess) run(dstPort int) {
	if s.h.cfg.IsTelnet(dstPort) {
		s.telnetMode = true
		s.telnet(nil)
		return
	}
	buf := make([]byte, 4096)
	n, _ := s.read(buf)
	if n == 0 {
		return
	}
	first := append([]byte(nil), buf[:n]...)
	switch parser.Detect(first) {
	case parser.HTTP:
		s.httpLoop(first)
	case parser.ADB:
		s.adbLoop(first)
	case parser.Telnet:
		s.telnetMode = true
		s.telnet(first)
	default:
		s.rawLoop(first)
	}
}

func (s *sess) read(p []byte) (int, error) {
	if s.total >= s.budget {
		s.ev.Truncated = true
		return 0, errReadLimit
	}
	now := time.Now()
	d := now.Add(s.h.cfg.ReadTimeout)
	if d.After(s.end) {
		d = s.end
	}
	if !d.After(now) {
		return 0, os.ErrDeadlineExceeded
	}
	if room := s.budget - s.total; len(p) > room {
		p = p[:room]
	}
	_ = s.conn.SetReadDeadline(d)
	n, err := s.conn.Read(p)
	s.total += n
	if n > 0 && len(s.raw) < s.h.cfg.MaxReadBytes {
		room := s.h.cfg.MaxReadBytes - len(s.raw)
		if room > n {
			room = n
		}
		s.raw = append(s.raw, p[:room]...)
	}
	return n, err
}

func (s *sess) write(b []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.h.cfg.WriteTimeout))
	_, err := s.conn.Write(b)
	return err
}

func (s *sess) writeString(str string) error { return s.write([]byte(str)) }

func (s *sess) line(format string, a ...any) {
	if s.text.Len() >= 2*s.h.cfg.MaxReadBytes {
		return
	}
	s.text.WriteString(parser.Sanitize([]byte(fmt.Sprintf(format, a...)), maxCommandLen*2))
	s.text.WriteByte('\n')
}

func (s *sess) addCommand(cmd string) {
	cmd = strings.TrimSpace(parser.Sanitize([]byte(cmd), maxCommandLen))
	if cmd == "" || cmd == "exit" || cmd == "logout" || len(s.ev.Commands) >= maxCommands {
		return
	}
	s.ev.Commands = append(s.ev.Commands, cmd)
	s.line("$ %s", cmd)
}

func (s *sess) rawLoop(first []byte) {
	s.ev.Protocol, s.ev.Action = string(parser.Raw), "Raw data"
	_ = first
	buf := make([]byte, 4096)
	for {
		if _, err := s.read(buf); err != nil {
			return
		}
	}
}

func (s *sess) httpLoop(first []byte) {
	s.ev.Protocol = string(parser.HTTP)
	buf := make([]byte, 4096)
	data := first

	for reqs := 0; reqs < maxHTTPRequests; reqs++ {
		req, used, st := parser.ParseHTTPRequest(data, false)
		for st == parser.NeedMore {
			n, err := s.read(buf)
			data = append(data, buf[:n]...)
			if err != nil {
				req, used, st = parser.ParseHTTPRequest(data, true)
				break
			}
			req, used, st = parser.ParseHTTPRequest(data, false)
		}
		if st != parser.Done {
			if len(data) > 0 && s.ev.HTTPMethod == "" {
				s.ev.Action = "HTTP (malformed)"
			}
			return
		}

		s.recordHTTP(req, reqs == 0)
		keep := req.KeepAlive && reqs+1 < maxHTTPRequests
		if err := s.write(s.httpReply(req, keep)); err != nil || !keep {
			return
		}
		data = data[used:]
		if len(data) == 0 {
			n, err := s.read(buf)
			if n == 0 || err != nil && n == 0 {
				return
			}
			data = append(data, buf[:n]...)
		}
	}
}

func (s *sess) recordHTTP(req *parser.HTTPRequest, first bool) {
	if !first {
		return
	}
	s.ev.HTTPMethod = parser.Truncate(parser.Sanitize([]byte(req.Method), 16), 16)
	s.ev.HTTPPath = parser.Truncate(parser.Sanitize([]byte(req.Target), 512), 512)
	s.ev.UserAgent = parser.Truncate(parser.Sanitize([]byte(req.UserAgent), 256), 256)
	s.ev.Action = "HTTP " + s.ev.HTTPMethod
}

const soapReply = `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body/></SOAP-ENV:Envelope>`

func httpResponse(req *parser.HTTPRequest, keepAlive bool) []byte {
	body, ctype := `<html><head><title>Router</title></head><body>OK</body></html>`, "text/html"
	if _, ok := req.Headers["Soapaction"]; ok || strings.Contains(strings.ToLower(string(req.Body)), "envelope") {
		body, ctype = soapReply, "text/xml"
	}
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 200 OK\r\nServer: Boa/0.94.14rc21\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: %s\r\n\r\n",
		ctype, len(body), conn)
	if req.Method != "HEAD" {
		b.WriteString(body)
	}
	return []byte(b.String())
}

func (s *sess) httpReply(req *parser.HTTPRequest, keep bool) []byte {
	vendor, ok := s.h.cfg.WebVendor(s.dstPort)
	if !ok {
		return httpResponse(req, keep)
	}
	wire, resp := s.h.web.Render(vendor, webcam.Request{
		Method: req.Method, Target: req.Target, Headers: req.Headers, Body: req.Body,
	}, keep)
	if s.ev.Persona == "" {
		s.ev.Persona = string(resp.Vendor)
	}
	if resp.Signature != "" && s.ev.Signature == "" {
		s.ev.Signature = resp.Signature
	}
	for _, c := range resp.Commands {
		s.addCommand(c)
	}
	for _, c := range resp.Credentials {
		if len(s.ev.Credentials) < maxCredentials {
			s.ev.Credentials = append(s.ev.Credentials, model.Credential{Username: c.Username, Password: c.Password})
		}
	}
	return wire
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
