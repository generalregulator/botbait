package session

import (
	"strings"

	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
)

type telnetState int

const (
	stLogin telnetState = iota
	stPassword
	stShell
)

func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func (s *sess) telnet(first []byte) {
	s.ev.Protocol, s.ev.Action = string(parser.Telnet), "Telnet connect"
	tp := s.h.telProf.Telnet

	_ = s.write(parser.TelnetNegotiation)
	if tp.Pre != "" {
		_ = s.writeString(crlf(tp.Pre))
	}
	_ = s.writeString("\r\n" + tp.LoginPrompt)

	state, failures := stLogin, 0
	var user string
	var lineBuf []byte
	prevCR := false
	sh := s.newShell()
	revSeen := 0

	prompt := func() { _ = s.writeString(sh.TelnetPrompt()) }

	handle := func(line string) (stop bool) {
		switch state {
		case stLogin:
			user = line
			state = stPassword
			_ = s.writeString("\r\n" + tp.PasswordPrompt)
		case stPassword:
			if len(s.ev.Credentials) < maxCredentials {
				s.ev.Credentials = append(s.ev.Credentials, model.Credential{
					Username: parser.Truncate(parser.Sanitize([]byte(user), 64), 64),
					Password: parser.Truncate(parser.Sanitize([]byte(line), 64), 64),
				})
			}
			s.line("login attempt: %s / %s", user, line)
			if failures < tp.FailuresBeforeOK {
				failures++
				state = stLogin
				_ = s.writeString("\r\n" + tp.FailureMessage + "\r\n" + tp.LoginPrompt)
				return false
			}
			state = stShell
			_ = s.writeString("\r\n" + crlf(tp.Welcome))
			prompt()
		case stShell:
			_ = s.writeString("\r\n")
			cmd := strings.TrimSpace(line)
			if cmd == "" {
				prompt()
				return false
			}
			s.addCommand(cmd)
			res := sh.Exec(cmd)
			s.recordRevealed(sh, &revSeen)
			out := crlf(string(res.Combined()))
			if out != "" && !strings.HasSuffix(out, "\r\n") {
				out += "\r\n"
			}
			_ = s.writeString(out)
			if res.Quit {
				return true
			}
			prompt()
		}
		return false
	}

	echo := func(b []byte) {
		if state == stPassword || len(b) == 0 {
			return
		}
		_ = s.write(b)
	}

	feed := func(chunk []byte) (stop bool) {
		for _, c := range parser.StripTelnet(chunk) {
			switch {
			case c == '\r':
				prevCR = true
				l := string(lineBuf)
				lineBuf = lineBuf[:0]
				if handle(l) {
					return true
				}
			case c == '\n':
				if prevCR {
					prevCR = false
					continue
				}
				l := string(lineBuf)
				lineBuf = lineBuf[:0]
				if handle(l) {
					return true
				}
			case c == 0:
				prevCR = false
			case c == 0x7f || c == 0x08:
				prevCR = false
				if len(lineBuf) > 0 {
					lineBuf = lineBuf[:len(lineBuf)-1]
					echo([]byte("\b \b"))
				}
			case c == 0x03 && state == stShell:
				prevCR = false
				lineBuf = lineBuf[:0]
				_ = s.writeString("^C\r\n")
				prompt()
			default:
				prevCR = false
				if len(lineBuf) < maxCommandLen {
					lineBuf = append(lineBuf, c)
					echo([]byte{c})
				}
			}
		}
		return false
	}

	defer func() {
		switch {
		case len(s.ev.Commands) > 0:
			s.ev.Action = "Telnet shell"
		case len(s.ev.Credentials) > 0:
			s.ev.Action = "Telnet login"
		}
	}()

	if len(first) > 0 && feed(first) {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := s.read(buf)
		if n > 0 && feed(buf[:n]) {
			return
		}
		if err != nil {
			if len(lineBuf) > 0 && state == stShell {
				s.addCommand(string(lineBuf))
			}
			return
		}
	}
}
