package redact

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplyIPv4(t *testing.T) {
	r := New()
	r.Add("185.237.185.88")
	cases := []struct{ in, want string }{
		{"Host: 185.237.185.88:80", "Host: [REDACTED]:80"},
		{"Host: 185.237.185.88", "Host: [REDACTED]"},
		{"http://185.237.185.88/a.sh and 185.237.185.88", "http://[REDACTED]/a.sh and [REDACTED]"},
		{"1185.237.185.88", "1185.237.185.88"},
		{"185.237.185.880", "185.237.185.880"},
		{"185.237.185.88.5", "185.237.185.88.5"},
		{"9.185.237.185.88", "9.185.237.185.88"},
		{"185.237.185.88.in-addr.arpa", "[REDACTED].in-addr.arpa"},
		{"(185.237.185.88)", "([REDACTED])"},
		{"nothing here", "nothing here"},
		{"", ""},
	}
	for _, c := range cases {
		if got := r.Apply(c.in); got != c.want {
			t.Errorf("Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestKeepAndDisjoint(t *testing.T) {
	r := New()
	r.Add("203.0.113.5")
	r.Add("198.51.100.7")
	got := r.Apply("a 203.0.113.5 b 198.51.100.7 c", "203.0.113.5")
	if got != "a 203.0.113.5 b [REDACTED] c" {
		t.Errorf("keep: %q", got)
	}
}

func TestHostnames(t *testing.T) {
	r := New()
	r.Add("https://Sensor.Example.com:8443/path")
	cases := map[string]string{
		"Host: sensor.example.com":                  "Host: [REDACTED]",
		"Host: SENSOR.EXAMPLE.COM:80":               "Host: [REDACTED]:80",
		"mysensor.example.com":                      "mysensor.example.com",
		"sensor.example.com.evil.net":               "sensor.example.com.evil.net",
		"x-sensor.example.com":                      "x-sensor.example.com",
		"see sensor.example.com.":                   "see [REDACTED].",
		"a sensor.example.com b sensor.example.com": "a [REDACTED] b [REDACTED]",
	}
	for in, want := range cases {
		if got := r.Apply(in); got != want {
			t.Errorf("Apply(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPv6(t *testing.T) {
	r := New()
	r.Add("2001:DB8::1")
	if got := r.Apply("Host: [2001:db8::1]:80"); got != "Host: [[REDACTED]]:80" {
		t.Errorf("%q", got)
	}
	if got := r.Apply("2001:db8::10"); got != "2001:db8::10" {
		t.Errorf("longer address changed: %q", got)
	}
}

func TestAddRejectsGarbage(t *testing.T) {
	r := New()
	for _, v := range []string{"", "  ", "localhost", "a b", "0.0.0.0", "::"} {
		if r.Add(v) {
			t.Errorf("accepted %q", v)
		}
	}
	if r.Len() != 0 {
		t.Error("garbage was stored")
	}
	if n := r.AddList("203.0.113.5, example.org;198.51.100.1 junk"); n != 3 {
		t.Errorf("AddList added %d", n)
	}
	if !r.Has("203.0.113.5:80") || !r.Has("EXAMPLE.org") || r.Has("8.8.8.8") {
		t.Error("Has")
	}
}

func TestNilAndEmptyAreNoOps(t *testing.T) {
	var r *Redactor
	if r.Apply("1.2.3.4") != "1.2.3.4" {
		t.Error("nil redactor changed text")
	}
	if New().Apply("1.2.3.4") != "1.2.3.4" {
		t.Error("empty redactor changed text")
	}
}

func TestAddInterfacesSkipsLoopback(t *testing.T) {
	r := New()
	r.AddInterfaces()
	if r.Has("127.0.0.1") || r.Has("::1") {
		t.Error("loopback was added")
	}
}

func TestDetectPublicIP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte("203.0.113.9\n"))
		case "/private":
			w.Write([]byte("10.0.0.1"))
		case "/html":
			w.Write([]byte("<html>hello</html>"))
		default:
			http.Error(w, "no", 500)
		}
	}))
	defer srv.Close()
	c := srv.Client()
	ctx := context.Background()
	if ip, err := DetectPublicIP(ctx, c, srv.URL+"/ok"); err != nil || ip != "203.0.113.9" {
		t.Errorf("ok: %q %v", ip, err)
	}
	for _, p := range []string{"/private", "/html", "/err"} {
		if ip, err := DetectPublicIP(ctx, c, srv.URL+p); err == nil {
			t.Errorf("%s accepted: %q", p, ip)
		}
	}
	if _, err := DetectPublicIP(ctx, nil, "http://example.com/"); err == nil {
		t.Error("plain http accepted")
	}
}

func TestWatchAddsAndStops(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("203.0.113.77"))
	}))
	defer srv.Close()
	r := New()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	got := make(chan string, 4)
	go func() {
		defer close(done)
		w := &watcher{r: r, client: srv.Client()}
		w.run(ctx, srv.URL, time.Hour, func(ip string, err error) { got <- ip })
	}()
	select {
	case ip := <-got:
		if ip != "203.0.113.77" || !r.Has(ip) {
			t.Errorf("detected %q", ip)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no detection")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
}

func TestWatchOffDoesNothing(t *testing.T) {
	r := New()
	r.Watch(context.Background(), "off", time.Hour, func(string, error) { t.Error("called") })
	r.Watch(context.Background(), "", time.Hour, nil)
	if r.Len() != 0 {
		t.Error("unexpected")
	}
}
