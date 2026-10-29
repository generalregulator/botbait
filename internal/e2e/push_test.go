package e2e

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/parser"
)

func syncMsg(id string, v uint32, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], v)
	return append(b, body...)
}

func TestADBPushEndToEnd(t *testing.T) {
	e := startEnv(t)

	bot := append([]byte("\x7fELF\x01\x01\x01\x00"), bytes.Repeat([]byte("mirai-like-payload"), 34000)...)
	sum := sha256.Sum256(bot)
	want := hex.EncodeToString(sum[:])

	a := dial(t, e.adbPort)
	send := func(cmd string, a0, a1 uint32, p []byte) {
		t.Helper()
		if _, err := a.Write(parser.BuildADB(cmd, a0, a1, p)); err != nil {
			t.Fatalf("write %s: %v", cmd, err)
		}
	}
	var inbuf []byte
	next := func() parser.ADBMessage {
		t.Helper()
		for {
			msgs, used, err := parser.ParseADB(inbuf, 1<<20)
			if err != nil {
				t.Fatalf("server sent invalid ADB: %v", err)
			}
			if len(msgs) > 0 {
				var rest []byte
				for _, m := range msgs[1:] {
					rest = append(rest, parser.BuildADB(m.Command, m.Arg0, m.Arg1, m.Payload)...)
				}
				inbuf = append(rest, inbuf[used:]...)
				return msgs[0]
			}
			_ = a.SetReadDeadline(time.Now().Add(4 * time.Second))
			tmp := make([]byte, 64<<10)
			n, err := a.Read(tmp)
			if n == 0 {
				t.Fatalf("read: %v", err)
			}
			inbuf = append(inbuf, tmp[:n]...)
		}
	}
	waitFor := func(cmd string) parser.ADBMessage {
		t.Helper()
		for i := 0; i < 100; i++ {
			if m := next(); m.Command == cmd {
				return m
			}
		}
		t.Fatalf("never saw %s", cmd)
		return parser.ADBMessage{}
	}

	send("CNXN", 0x01000001, 256*1024, []byte("host::features=shell_v2\x00"))
	waitFor("CNXN")

	send("OPEN", 1, 0, []byte("sync:\x00"))
	id := waitFor("OKAY").Arg0
	send("WRTE", 1, id, syncMsg("SEND", uint32(len("/data/local/tmp/bot,33261")), []byte("/data/local/tmp/bot,33261")))
	for off := 0; off < len(bot); off += 64 * 1024 {
		end := min(off+64*1024, len(bot))
		send("WRTE", 1, id, syncMsg("DATA", uint32(end-off), bot[off:end]))
	}
	send("WRTE", 1, id, syncMsg("DONE", 1700000000, nil))
	if ack := waitFor("WRTE"); string(ack.Payload[:4]) != "OKAY" {
		t.Fatalf("push not acknowledged: %q", ack.Payload)
	}
	send("WRTE", 1, id, syncMsg("QUIT", 0, nil))
	waitFor("CLSE")

	readOut := func(cmd string, local uint32) string {
		t.Helper()
		send("OPEN", local, 0, []byte("shell:"+cmd+"\x00"))
		waitFor("OKAY")
		var out []byte
		for {
			m := next()
			if m.Command == "WRTE" {
				out = append(out, m.Payload...)
			}
			if m.Command == "CLSE" {
				return string(out)
			}
		}
	}
	md5want := fmt.Sprintf("%x", md5.Sum(bot))
	if out := readOut("md5sum /data/local/tmp/bot", 5); !strings.HasPrefix(out, md5want+"  /data/local/tmp/bot") {
		t.Fatalf("md5sum of the uploaded file: %q (want %s)", out, md5want)
	}
	if out := readOut("head -c 4 /data/local/tmp/bot | od -An -tx1", 6); strings.TrimSpace(out) != "7f 45 4c 46" {
		t.Fatalf("head -c on the uploaded file: %q", out)
	}
	if out := readOut("cat /data/local/tmp/bot | wc -c", 7); strings.TrimSpace(out) == "0" {
		t.Fatalf("cat of the uploaded file is empty")
	}

	send("OPEN", 2, 0, []byte("shell:chmod 755 /data/local/tmp/bot; /data/local/tmp/bot; rm -f /data/local/tmp/bot; echo done\x00"))
	waitFor("OKAY")
	var out []byte
	for {
		m := next()
		if m.Command == "WRTE" {
			out = append(out, m.Payload...)
		}
		if m.Command == "CLSE" {
			break
		}
	}
	if strings.TrimSpace(string(out)) != "done" {
		t.Fatalf("shell output: %q", out)
	}
	a.Close()

	msg := e.waitAlert(t)
	for _, w := range []string{
		fmt.Sprintf("(%d/ADB)", e.adbPort), "T1105 (Ingress Tool Transfer)", "T1059.004",
		"📎 Dropped: /data/local/tmp/bot (adb-sync-push)", "SHA256: <code>" + want + "</code>", "(ELF)",
	} {
		if !strings.Contains(msg, w) {
			t.Errorf("alert missing %q:\n%s", w, msg)
		}
	}

	path := filepath.Join(e.ps.Dir(), want+".bin")
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, bot) {
		t.Fatalf("captured sample differs: err=%v len=%d want=%d", err, len(got), len(bot))
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("sample mode %v", st.Mode())
	}

	events := e.shutdown(t)
	var found bool
	for _, ev := range events {
		for _, d := range ev.Dropped {
			if d.SHA256 == want {
				found = true
				if d.Path != "/data/local/tmp/bot" || d.Mode != "0755" || !d.Executable || d.FileType != "ELF" || !d.Success {
					t.Errorf("drop record: %+v", d)
				}
				if !ev.HasTechnique("T1105") {
					t.Errorf("T1105 missing: %v", ev.TechniqueIDs())
				}
			}
		}
	}
	if !found {
		t.Fatalf("no event carries the dropped file; events=%d", len(events))
	}
	if e.m.FilesCaptured.Load() != 1 {
		t.Fatalf("metric files_captured=%d", e.m.FilesCaptured.Load())
	}
}
