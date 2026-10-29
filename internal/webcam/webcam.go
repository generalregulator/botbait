package webcam

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Vendor string

const (
	Hikvision Vendor = "hikvision"
	Dahua     Vendor = "dahua"
	TVT       Vendor = "tvt"
)

func ParseVendor(s string) (Vendor, bool) {
	switch v := Vendor(strings.ToLower(strings.TrimSpace(s))); v {
	case Hikvision, Dahua, TVT:
		return v, true
	}
	return "", false
}

func Vendors() []Vendor { return []Vendor{Hikvision, Dahua, TVT} }

type Request struct {
	Method  string
	Target  string
	Headers map[string]string
	Body    []byte
}

type Credential struct{ Username, Password string }

type Response struct {
	Status      int
	Server      string
	ContentType string
	Extra       [][2]string
	Body        []byte

	Vendor      Vendor
	Signature   string
	Commands    []string
	Credentials []Credential
}

type Identity struct {
	Seed   string
	hash   [32]byte
	Serial map[Vendor]string
	MAC    map[Vendor]string
	Model  map[Vendor]string
}

func NewIdentity(seed string) *Identity {
	h := sha256.Sum256([]byte("botbait/webcam/v1|" + seed))
	id := &Identity{Seed: seed, hash: h, Serial: map[Vendor]string{}, MAC: map[Vendor]string{}, Model: map[Vendor]string{}}
	digits := func(off, n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte('0' + h[(off+i)%32]%10)
		}
		return b.String()
	}
	mac := func(oui string, off int) string {
		return fmt.Sprintf("%s:%02x:%02x:%02x", oui, h[off%32], h[(off+1)%32], h[(off+2)%32])
	}
	id.Model[Hikvision] = "DS-2CD2032-I"
	id.Serial[Hikvision] = "DS-2CD2032-I20160418AACH" + digits(0, 9)
	id.MAC[Hikvision] = mac("c0:56:e3", 9)

	id.Model[Dahua] = "IPC-HFW1230S"
	id.Serial[Dahua] = "4C" + strings.ToUpper(hex.EncodeToString(h[12:19]))
	id.MAC[Dahua] = mac("3c:ef:8c", 19)

	id.Model[TVT] = "TD-2104TS-CL"
	id.Serial[TVT] = "TVT" + digits(22, 10)
	id.MAC[TVT] = mac("00:18:ae", 24)
	return id
}

func (id *Identity) token(label string, n int) string {
	h := sha256.Sum256(append(id.hash[:], label...))
	return hex.EncodeToString(h[:])[:n]
}

type Server struct {
	id  *Identity
	now func() time.Time
}

func New(seed string) *Server { return &Server{id: NewIdentity(seed), now: time.Now} }

func (s *Server) Identity() *Identity { return s.id }

func (s *Server) Respond(def Vendor, r Request) Response {
	u, err := url.ParseRequestURI(r.Target)
	if err != nil {
		u = &url.URL{Path: "/"}
	}
	path := strings.ToLower(u.Path)
	v := def
	if fp, ok := fingerprint(path); ok {
		v = fp
	}
	p := &ctx{s: s, r: r, u: u, path: path, query: u.Query(), v: v}
	p.user, p.pass, p.authed = credentials(r.Headers)
	if p.authed {
		p.creds = append(p.creds, Credential{p.user, p.pass})
	}
	switch v {
	case Dahua:
		p.dahua()
	case TVT:
		p.tvt()
	default:
		p.hikvision()
	}
	if p.resp.Status == 0 {
		p.notFound()
	}
	p.resp.Credentials = p.creds
	p.resp.Vendor = v
	return p.resp
}

func fingerprint(path string) (Vendor, bool) {
	switch {
	case strings.HasPrefix(path, "/rpc2"), strings.HasPrefix(path, "/cgi-bin/magicbox.cgi"),
		strings.HasPrefix(path, "/cgi-bin/usermanager.cgi"), strings.HasPrefix(path, "/cgi-bin/configmanager.cgi"),
		strings.HasPrefix(path, "/cgi-bin/snapshot.cgi"), strings.HasPrefix(path, "/current_config/"):
		return Dahua, true
	case strings.HasPrefix(path, "/sdk/"), strings.HasPrefix(path, "/isapi/"), strings.HasPrefix(path, "/system/"),
		strings.HasPrefix(path, "/security/"), strings.HasPrefix(path, "/onvif-http/"),
		strings.HasPrefix(path, "/doc/page/"), strings.HasPrefix(path, "/streaming/"),
		strings.HasPrefix(path, "/bic/"):
		return Hikvision, true
	}
	return "", false
}

func (r *Response) Bytes(method string, keepAlive bool, now time.Time) []byte {
	conn := "close"
	if keepAlive {
		conn = "keep-alive"
	}
	reason := http.StatusText(r.Status)
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", r.Status, reason)
	fmt.Fprintf(&b, "Date: %s\r\n", now.UTC().Format(http.TimeFormat))
	if r.Server != "" {
		fmt.Fprintf(&b, "Server: %s\r\n", r.Server)
	}
	if r.ContentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", r.ContentType)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(r.Body))
	for _, h := range r.Extra {
		fmt.Fprintf(&b, "%s: %s\r\n", h[0], h[1])
	}
	fmt.Fprintf(&b, "Connection: %s\r\n\r\n", conn)
	if method != "HEAD" {
		b.Write(r.Body)
	}
	return b.Bytes()
}

func (s *Server) Render(def Vendor, r Request, keepAlive bool) ([]byte, Response) {
	resp := s.Respond(def, r)
	return resp.Bytes(r.Method, keepAlive, s.now()), resp
}

type ctx struct {
	s      *Server
	r      Request
	u      *url.URL
	path   string
	query  url.Values
	v      Vendor
	resp   Response
	creds  []Credential
	user   string
	pass   string
	authed bool
}

func (c *ctx) set(status int, ctype string, body []byte, server string) {
	c.resp.Status, c.resp.ContentType, c.resp.Body, c.resp.Server = status, ctype, body, server
}

func (c *ctx) html(status int, server, body string) {
	c.set(status, "text/html", []byte(body), server)
}

func (c *ctx) notFound() {
	server := serverHeader(c.v)
	c.html(404, server, "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>")
}

func (c *ctx) digest(server, realm string) {
	nonce := c.s.id.token("nonce|"+c.r.Target+c.s.now().Format("150405"), 32)
	c.set(401, "text/html", []byte("<html><head><title>401 Unauthorized</title></head><body>401 Unauthorized</body></html>"), server)
	c.resp.Extra = append(c.resp.Extra, [2]string{"WWW-Authenticate",
		fmt.Sprintf(`Digest realm="%s", qop="auth", nonce="%s", opaque="", stale="FALSE"`, realm, nonce)})
}

func serverHeader(v Vendor) string {
	switch v {
	case Dahua:
		return "Webs"
	case TVT:
		return "nginx"
	}
	return "App-webs/"
}

var (
	substRe  = regexp.MustCompile("\\$\\(([^)]{1,1000})\\)|`([^`]{1,1000})`")
	langRe   = regexp.MustCompile(`(?is)<\s*language\s*>(.*?)<\s*/\s*language\s*>`)
	authRe   = regexp.MustCompile(`(?i)^\s*(basic|digest)\s+(.+)$`)
	digestUN = regexp.MustCompile(`(?i)username\s*=\s*"([^"]{0,64})"`)
)

func extractCommands(s string) []string {
	var out []string
	for _, m := range substRe.FindAllStringSubmatch(s, 8) {
		cmd := strings.TrimSpace(m[1] + m[2])
		if cmd != "" {
			out = append(out, cmd)
		}
	}
	return out
}

func credentials(h map[string]string) (user, pass string, ok bool) {
	raw := h["Authorization"]
	m := authRe.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	switch strings.ToLower(m[1]) {
	case "basic":
		dec, err := decodeBase64(strings.TrimSpace(m[2]))
		if err != nil {
			return "", "", false
		}
		u, p, found := strings.Cut(dec, ":")
		if !found {
			return "", "", false
		}
		return clip(u, 64), clip(p, 64), true
	default:
		if d := digestUN.FindStringSubmatch(m[2]); d != nil {
			return d[1], "(digest response)", true
		}
	}
	return "", "", false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
