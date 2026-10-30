package redact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const Placeholder = "[REDACTED]"

type Redactor struct {
	mu    sync.RWMutex
	ips   map[string]bool
	hosts map[string]bool
}

func New() *Redactor {
	return &Redactor{ips: map[string]bool{}, hosts: map[string]bool{}}
}

func normalise(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return strings.Trim(strings.ToLower(v), "[]. ")
}

func (r *Redactor) Add(v string) bool {
	v = normalise(v)
	if v == "" || strings.ContainsAny(v, " \t,;") {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, err := netip.ParseAddr(v); err == nil {
		a = a.Unmap().WithZone("")
		if a.IsUnspecified() {
			return false
		}
		r.ips[a.String()] = true
		return true
	}
	if !strings.Contains(v, ".") || len(v) > 253 {
		return false
	}
	r.hosts[v] = true
	return true
}

func (r *Redactor) AddList(csv string) int {
	n := 0
	for _, f := range strings.FieldsFunc(csv, func(c rune) bool { return c == ',' || c == ';' || c == ' ' || c == '\n' }) {
		if r.Add(f) {
			n++
		}
	}
	return n
}

func (r *Redactor) AddInterfaces() int {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0
	}
	n := 0
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		if r.Add(ip.String()) {
			n++
		}
	}
	return n
}

func (r *Redactor) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.ips) + len(r.hosts)
}

func (r *Redactor) Has(v string) bool {
	v = normalise(v)
	if a, err := netip.ParseAddr(v); err == nil {
		v = a.Unmap().String()
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ips[v] || r.hosts[v]
}

func (r *Redactor) Apply(s string, keep ...string) string {
	if r == nil || s == "" {
		return s
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.ips) == 0 && len(r.hosts) == 0 {
		return s
	}
	skip := map[string]bool{}
	for _, k := range keep {
		if k = normalise(k); k != "" {
			skip[k] = true
		}
	}
	lower := strings.ToLower(s)
	type span struct{ a, b int }
	var spans []span
	scan := func(needle string, isIP bool) {
		if skip[needle] {
			return
		}
		for from := 0; ; {
			i := strings.Index(lower[from:], needle)
			if i < 0 {
				return
			}
			a := from + i
			b := a + len(needle)
			from = b
			if boundaryOK(lower, a, b, isIP, strings.Contains(needle, ":")) {
				spans = append(spans, span{a, b})
			}
		}
	}
	for ip := range r.ips {
		scan(ip, true)
	}
	for h := range r.hosts {
		scan(h, false)
	}
	if len(spans) == 0 {
		return s
	}
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0 && spans[j].a < spans[j-1].a; j-- {
			spans[j], spans[j-1] = spans[j-1], spans[j]
		}
	}
	var b strings.Builder
	pos := 0
	for _, sp := range spans {
		if sp.a < pos {
			continue
		}
		b.WriteString(s[pos:sp.a])
		b.WriteString(Placeholder)
		pos = sp.b
	}
	b.WriteString(s[pos:])
	return b.String()
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f')
}

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z')
}

func boundaryOK(s string, a, b int, isIP, v6 bool) bool {
	var prev, next byte
	if a > 0 {
		prev = s[a-1]
	}
	if b < len(s) {
		next = s[b]
	}
	switch {
	case isIP && v6:
		return !(isHex(prev) || prev == ':') && !(isHex(next) || (next == ':' && b+1 < len(s) && (isHex(s[b+1]) || s[b+1] == ':')))
	case isIP:
		if isDigit(prev) || (prev == '.' && a >= 2 && isDigit(s[a-2])) {
			return false
		}
		if isDigit(next) || (next == '.' && b+1 < len(s) && isDigit(s[b+1])) {
			return false
		}
		return true
	default:
		if isAlnum(prev) || prev == '-' || prev == '_' {
			return false
		}
		if isAlnum(next) || next == '-' || next == '_' {
			return false
		}
		if next == '.' && b+1 < len(s) && isAlnum(s[b+1]) {
			return false
		}
		return true
	}
}

func DetectPublicIP(ctx context.Context, client *http.Client, url string) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if !strings.HasPrefix(url, "https://") {
		return "", errors.New("the public IP service must be an https:// URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "botbait-honeypot")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("public IP service answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return "", errors.New("the public IP service did not return an IP address")
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return "", errors.New("the public IP service returned a non-public address")
	}
	return ip.String(), nil
}

func (r *Redactor) Watch(ctx context.Context, url string, every time.Duration, onChange func(ip string, err error)) {
	w := &watcher{r: r}
	w.run(ctx, url, every, onChange)
}

type watcher struct {
	r      *Redactor
	client *http.Client
}

func (w *watcher) run(ctx context.Context, url string, every time.Duration, onChange func(ip string, err error)) {
	if url == "" || strings.EqualFold(url, "off") {
		return
	}
	check := func() {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		defer cancel()
		ip, err := DetectPublicIP(cctx, w.client, url)
		if err == nil {
			w.r.Add(ip)
		}
		if onChange != nil {
			onChange(ip, err)
		}
	}
	check()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}
