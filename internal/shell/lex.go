package shell

import "strings"

const (
	tWord = iota
	tOp
)

type tok struct {
	kind int
	s    string
}

const (
	opSemi = ";"
	opAnd  = "&&"
	opOr   = "||"
	opPipe = "|"
	opBg   = "&"
)

func isRedir(op string) bool {
	switch op {
	case ">", ">>", "2>", "2>>", "&>", "&>>", "<", "<<", "2>&1", ">&2":
		return true
	}
	return false
}

func isWordEnd(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', ';', '|', '&', '<', '>', '(', ')':
		return true
	}
	return false
}

const maxTokens = 2048

func lex(line string) []tok {
	var out []tok
	i, n := 0, len(line)
	emit := func(k int, s string) {
		if len(out) < maxTokens {
			out = append(out, tok{k, s})
		}
	}
	for i < n {
		c := line[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '\n':
			emit(tOp, opSemi)
			i++
		case c == '#':

			for i < n && line[i] != '\n' {
				i++
			}
		case c == ';':
			if i+1 < n && line[i+1] == ';' {
				i++
			}
			emit(tOp, opSemi)
			i++
		case c == '(' || c == ')':
			i++
		case c == '|':
			if i+1 < n && line[i+1] == '|' {
				emit(tOp, opOr)
				i += 2
			} else {
				emit(tOp, opPipe)
				i++
			}
		case c == '&':
			switch {
			case i+1 < n && line[i+1] == '&':
				emit(tOp, opAnd)
				i += 2
			case i+2 < n && line[i+1] == '>' && line[i+2] == '>':
				emit(tOp, "&>>")
				i += 3
			case i+1 < n && line[i+1] == '>':
				emit(tOp, "&>")
				i += 2
			default:
				emit(tOp, opBg)
				i++
			}
		case c == '>':
			i = lexGreater(line, i, "1", emit)
		case c == '<':
			if i+1 < n && line[i+1] == '<' {
				i += 2
				if i < n && line[i] == '-' {
					i++
				}
				emit(tOp, "<<")
			} else {
				emit(tOp, "<")
				i++
			}
		default:
			j := scanWord(line, i)
			w := line[i:j]

			if j < n && (line[j] == '>' || line[j] == '<') && allDigits(w) {
				if line[j] == '>' {
					i = lexGreater(line, j, w, emit)
				} else {
					emit(tOp, "<")
					i = j + 1
				}
				continue
			}
			emit(tWord, w)
			i = j
		}
	}
	return out
}

func lexGreater(line string, i int, fd string, emit func(int, string)) int {
	n := len(line)

	switch {
	case i+1 < n && line[i+1] == '&':
		j := i + 2
		k := j
		for k < n && line[k] >= '0' && line[k] <= '9' {
			k++
		}
		target := line[j:k]
		switch {
		case fd == "2" && target == "1":
			emit(tOp, "2>&1")
		case fd == "1" && target == "2":
			emit(tOp, ">&2")
		case target == "":
			emit(tOp, "&>")
		}
		return k
	case i+1 < n && line[i+1] == '>':
		if fd == "2" {
			emit(tOp, "2>>")
		} else {
			emit(tOp, ">>")
		}
		return i + 2
	}
	if fd == "2" {
		emit(tOp, "2>")
	} else {
		emit(tOp, ">")
	}
	return i + 1
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func scanWord(line string, i int) int {
	n := len(line)
	for i < n {
		c := line[i]
		switch {
		case c == '\\':
			i += 2
		case c == '\'':
			i++
			for i < n && line[i] != '\'' {
				i++
			}
			i++
		case c == '"':
			i++
			for i < n && line[i] != '"' {
				if line[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '`':
			i++
			for i < n && line[i] != '`' {
				i++
			}
			i++
		case c == '$' && i+1 < n && (line[i+1] == '(' || line[i+1] == '{'):
			open, closeCh := line[i+1], byte(')')
			if open == '{' {
				closeCh = '}'
			}
			depth := 0
			i++
			for i < n {
				if line[i] == open {
					depth++
				} else if line[i] == closeCh {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				i++
			}
		case isWordEnd(c):
			if i > n {
				return n
			}
			return i
		default:
			i++
		}
	}
	if i > n {
		return n
	}
	return i
}

func (s *Shell) expandWord(w string) (val string, glob bool) {
	var b strings.Builder
	n := len(w)
	if strings.HasPrefix(w, "~") && (n == 1 || w[1] == '/') {
		b.WriteString(s.env["HOME"])
		w = w[1:]
		n = len(w)
	}
	for i := 0; i < n; {
		c := w[i]
		switch {
		case c == '\\':
			if i+1 < n {
				b.WriteByte(w[i+1])
			}
			i += 2
		case c == '\'':
			j := strings.IndexByte(w[i+1:], '\'')
			if j < 0 {
				b.WriteString(w[i+1:])
				i = n
			} else {
				b.WriteString(w[i+1 : i+1+j])
				i += j + 2
			}
		case c == '"':
			i++
			for i < n && w[i] != '"' {
				switch {
				case w[i] == '\\' && i+1 < n && strings.IndexByte("\"\\$`\n", w[i+1]) >= 0:
					b.WriteByte(w[i+1])
					i += 2
				case w[i] == '$':
					i = s.expandVar(w, i, &b)
				default:
					b.WriteByte(w[i])
					i++
				}
			}
			i++
		case c == '$':
			i = s.expandVar(w, i, &b)
		case c == '*' || c == '?' || c == '[':
			glob = true
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), glob
}

func (s *Shell) expandVar(w string, i int, b *strings.Builder) int {
	n := len(w)
	if i+1 >= n {
		b.WriteByte('$')
		return i + 1
	}
	switch c := w[i+1]; {
	case c == '?':
		b.WriteString(itoa(s.lastExit))
		return i + 2
	case c == '$':
		b.WriteString("2231")
		return i + 2
	case c == '(':
		j := scanWord(w, i)
		b.WriteString(w[i:j])
		return j
	case c == '{':
		j := strings.IndexByte(w[i:], '}')
		if j < 0 {
			b.WriteString(w[i:])
			return n
		}
		name := w[i+2 : i+j]
		if k := strings.IndexAny(name, ":-=+?#%"); k > 0 {
			def := ""
			if rest := name[k:]; len(rest) > 2 && (rest[:2] == ":-" || rest[:2] == ":=") {
				def = rest[2:]
			}
			name = name[:k]
			if v := s.env[name]; v != "" {
				b.WriteString(v)
			} else {
				b.WriteString(def)
			}
			return i + j + 1
		}
		b.WriteString(s.env[name])
		return i + j + 1
	case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		j := i + 1
		for j < n && (w[j] == '_' || (w[j] >= 'A' && w[j] <= 'Z') || (w[j] >= 'a' && w[j] <= 'z') || (w[j] >= '0' && w[j] <= '9')) {
			j++
		}
		b.WriteString(s.env[w[i+1:j]])
		return j
	case c >= '0' && c <= '9':
		if c == '0' {
			b.WriteString("sh")
		}
		return i + 2
	}
	b.WriteByte('$')
	return i + 1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
