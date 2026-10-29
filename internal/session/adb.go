package session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/shell"
)

const (
	adbVersion = 0x01000001
	adbMaxData = 256 * 1024
)

type streamKind int

const (
	kShell streamKind = iota
	kSync
	kStatic
)

type adbStream struct {
	id, remote  uint32
	kind        streamKind
	v2, pty     bool
	interactive bool
	sh          *shell.Shell
	revSeen     int
	line        []byte
	prevCR      bool
	inbuf       []byte
	sync        *syncState
}

type adbSession struct {
	s         *sess
	streams   map[uint32]*adbStream
	next      uint32
	clientMax int
	hasShell  bool
	hasPush   bool
	hasPull   bool
}

func (s *sess) adbLoop(first []byte) {
	s.ev.Protocol, s.ev.Action = string(parser.ADB), "ADB connect"
	a := &adbSession{s: s, streams: map[uint32]*adbStream{}, next: 1, clientMax: 4096}
	defer a.closeAll()

	buf := make([]byte, 32*1024)
	data := first
	for {
		msgs, used, perr := parser.ParseADB(data, adbMaxData)
		data = data[used:]
		for _, m := range msgs {
			a.handle(m)
		}
		if perr != nil {
			s.line("[invalid ADB framing] %s", parser.Truncate(string(data), 1024))
			return
		}
		n, rerr := s.read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if rerr != nil {
			if n > 0 {
				msgs, _, _ := parser.ParseADB(data, adbMaxData)
				for _, m := range msgs {
					a.handle(m)
				}
			}
			return
		}
	}
}

func (a *adbSession) send(cmd string, arg0, arg1 uint32, payload []byte) {
	_ = a.s.write(parser.BuildADB(cmd, arg0, arg1, payload))
}

func (a *adbSession) handle(m parser.ADBMessage) {
	s := a.s
	switch m.Command {
	case "CNXN", "AUTH":
		if m.Command == "CNXN" && m.Arg1 >= 4096 {
			a.clientMax = int(min(m.Arg1, adbMaxData))
		}
		s.line("ADB %s %s", m.Command, parser.Truncate(trimNul(m.Payload), 256))
		a.send("CNXN", adbVersion, adbMaxData, []byte(s.h.adbProf.ADBBanner()+"\x00"))
	case "OPEN":
		a.open(m)
	case "WRTE":
		st := a.streams[m.Arg1]
		if st == nil || st.remote != m.Arg0 {
			return
		}
		a.send("OKAY", st.id, st.remote, nil)
		a.input(st, m.Payload)
	case "CLSE":
		if st := a.streams[m.Arg1]; st != nil {
			a.close(st, true)
		}
	case "OKAY":

	}
}

func trimNul(b []byte) string { return strings.TrimRight(string(b), "\x00") }

func (a *adbSession) open(m parser.ADBMessage) {
	s := a.s
	service := trimNul(m.Payload)
	s.line("ADB OPEN %s", parser.Truncate(service, maxCommandLen))

	if len(a.streams) >= 32 {
		a.send("CLSE", 0, m.Arg0, nil)
		return
	}
	st := &adbStream{id: a.next, remote: m.Arg0}
	name, rest, _ := strings.Cut(service, ":")
	head := strings.Split(name, ",")
	accept := func() { a.next++; a.streams[st.id] = st; a.send("OKAY", st.id, st.remote, nil) }

	switch head[0] {
	case "shell", "exec":
		st.kind = kShell
		for _, opt := range head[1:] {
			switch {
			case opt == "v2":
				st.v2 = true
			case opt == "pty":
				st.pty = true
			}
		}
		if head[0] == "shell" && !st.v2 {
			st.pty = true
		}
		accept()
		a.hasShell = true
		a.updateAction()
		a.startShell(st, rest)
	case "sync":
		st.kind = kSync
		st.sync = newSyncState(a, st)
		accept()
		a.updateAction()
	case "root", "unroot":
		accept()
		a.reply(st, "adbd is already running as root\n")
	case "remount":
		accept()
		a.reply(st, "remount succeeded\n")
	case "tcpip":
		accept()
		a.reply(st, fmt.Sprintf("restarting in TCP mode port: %s\n", rest))
	case "usb":
		accept()
		a.reply(st, "restarting in USB mode\n")
	case "reboot":
		accept()
		a.close(st, false)
		s.line("ADB reboot requested")
		s.end = time.Now()
	case "tcp", "local", "localabstract", "localfilesystem", "dev", "jdwp", "reverse", "forward":

		s.line("ADB forward/proxy attempt: %s", parser.Truncate(service, 256))
		if s.ev.Action == "ADB connect" {
			s.ev.Action = "ADB forward attempt"
		}
		a.send("CLSE", 0, m.Arg0, nil)
	default:
		a.send("CLSE", 0, m.Arg0, nil)
	}
}

func (a *adbSession) reply(st *adbStream, text string) {
	a.write(st, []byte(text))
	a.close(st, false)
}

func (a *adbSession) updateAction() {
	switch {
	case a.hasShell && a.hasPush:
		a.s.ev.Action = "ADB shell + push"
	case a.hasPush:
		a.s.ev.Action = "ADB push (file transfer)"
	case a.hasShell:
		a.s.ev.Action = "ADB shell"
	case a.hasPull:
		a.s.ev.Action = "ADB pull (file read)"
	}
}

func (a *adbSession) write(st *adbStream, data []byte) {
	chunk := a.clientMax
	if chunk < 4096 {
		chunk = 4096
	}
	for len(data) > 0 {
		n := len(data)
		if n > chunk {
			n = chunk
		}
		a.send("WRTE", st.id, st.remote, data[:n])
		data = data[n:]
	}
}

func (a *adbSession) close(st *adbStream, fromPeer bool) {
	if _, ok := a.streams[st.id]; !ok {
		return
	}
	if st.sync != nil {
		st.sync.finish(true)
	}
	delete(a.streams, st.id)
	a.send("CLSE", st.id, st.remote, nil)
}

func (a *adbSession) closeAll() {
	for _, st := range a.streams {
		if st.sync != nil {
			st.sync.finish(true)
		}
	}
}

func (a *adbSession) startShell(st *adbStream, cmd string) {
	st.sh = a.s.newShell()
	if strings.TrimSpace(cmd) == "" {
		st.interactive = true
		a.emit(st, []byte(st.sh.Prompt()), nil, -1)
		return
	}
	a.runCommand(st, cmd, true)
}

func (a *adbSession) runCommand(st *adbStream, cmd string, oneShot bool) {
	s := a.s
	s.addCommand(cmd)
	res := st.sh.Exec(cmd)
	s.recordRevealed(st.sh, &st.revSeen)

	exit := res.Exit
	switch {
	case oneShot || res.Quit:
		a.emit(st, res.Stdout, res.Stderr, exit)
		a.close(st, false)
	default:
		a.emit(st, res.Stdout, res.Stderr, -1)
		a.emit(st, []byte(st.sh.Prompt()), nil, -1)
	}
}

func (a *adbSession) emit(st *adbStream, stdout, stderr []byte, exit int) {
	if st.v2 {
		var out bytes.Buffer
		pkt := func(id byte, b []byte) {
			if len(b) == 0 {
				return
			}
			var hdr [5]byte
			hdr[0] = id
			binary.LittleEndian.PutUint32(hdr[1:], uint32(len(b)))
			out.Write(hdr[:])
			out.Write(b)
		}
		pkt(1, a.eol(st, stdout))
		pkt(2, a.eol(st, stderr))
		if exit >= 0 {
			pkt(3, []byte{byte(exit)})
		}
		a.write(st, out.Bytes())
		return
	}
	merged := append(append([]byte(nil), stdout...), stderr...)
	a.write(st, a.eol(st, merged))
}

func (a *adbSession) eol(st *adbStream, b []byte) []byte {
	if !st.pty || len(b) == 0 {
		return b
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}

func (a *adbSession) input(st *adbStream, data []byte) {
	switch st.kind {
	case kSync:
		st.sync.feed(data)
		a.updateAction()
	case kShell:
		if !st.interactive {
			return
		}
		if st.v2 {
			st.inbuf = append(st.inbuf, data...)
			for len(st.inbuf) >= 5 {
				n := int(binary.LittleEndian.Uint32(st.inbuf[1:5]))
				if n < 0 || n > adbMaxData {
					st.inbuf = nil
					return
				}
				if len(st.inbuf) < 5+n {
					return
				}
				id, payload := st.inbuf[0], st.inbuf[5:5+n]
				st.inbuf = st.inbuf[5+n:]
				if id == 0 {
					a.typed(st, payload)
				}
			}
			return
		}
		a.typed(st, data)
	}
}

func (a *adbSession) typed(st *adbStream, data []byte) {
	var echo []byte
	flush := func() {
		if len(echo) > 0 {
			a.emit(st, echo, nil, -1)
			echo = nil
		}
	}
	defer flush()
	for _, c := range data {
		if _, ok := a.streams[st.id]; !ok {
			return
		}
		switch {
		case c == '\r' || c == '\n':
			if c == '\n' && st.prevCR {
				st.prevCR = false
				continue
			}
			st.prevCR = c == '\r'
			if st.pty {
				echo = append(echo, '\r', '\n')
			}
			flush()
			line := string(st.line)
			st.line = st.line[:0]
			if strings.TrimSpace(line) == "" {
				a.emit(st, []byte(st.sh.Prompt()), nil, -1)
				continue
			}
			a.runCommand(st, line, false)
		case c == 0x7f || c == 0x08:
			st.prevCR = false
			if len(st.line) > 0 {
				st.line = st.line[:len(st.line)-1]
				if st.pty {
					echo = append(echo, '\b', ' ', '\b')
				}
			}
		case c == 0x03:
			st.prevCR = false
			st.line = st.line[:0]
			echo = append(echo, []byte("^C\r\n"+st.sh.Prompt())...)
		case c == 0x04 && len(st.line) == 0:
			flush()
			a.close(st, false)
			return
		case c >= 0x20 || c == '\t':
			st.prevCR = false
			if len(st.line) < maxCommandLen {
				st.line = append(st.line, c)
				if st.pty {
					echo = append(echo, c)
				}
			}
		}
	}
}
