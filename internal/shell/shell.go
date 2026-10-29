package shell

import (
	"bytes"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/generalregulator/botbait/internal/profile"
	"github.com/generalregulator/botbait/internal/vfs"
)

const (
	maxSteps      = 300
	maxDepth      = 4
	maxLoopIter   = 16
	maxOutput     = 128 << 10
	maxRevealed   = 200
	maxScriptLine = 1024
)

type Options struct {
	Now   func() time.Time
	Start time.Time
}

type Result struct {
	Stdout []byte
	Stderr []byte
	Exit   int
	Quit   bool
}

func (r Result) Combined() []byte {
	if len(r.Stderr) == 0 {
		return r.Stdout
	}
	return append(append([]byte(nil), r.Stdout...), r.Stderr...)
}

type Shell struct {
	p     *profile.Profile
	fs    *vfs.FS
	cwd   string
	env   map[string]string
	props map[string]string
	now   func() time.Time
	start time.Time

	lastExit int
	steps    int
	depth    int
	quit     bool
	revealed []string
}

func New(p *profile.Profile, fs *vfs.FS, o Options) *Shell {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Start.IsZero() {
		o.Start = o.Now()
	}
	s := &Shell{p: p, fs: fs, now: o.Now, start: o.Start, cwd: "/"}
	home := p.Shell.Home
	if home == "" {
		home = "/"
	}
	s.env = map[string]string{
		"HOME": home, "USER": p.Shell.User, "LOGNAME": p.Shell.User, "SHELL": s.shellPath(),
		"PATH": p.Shell.Path, "PWD": "/", "TERM": "xterm", "HOSTNAME": p.Hostname,
	}
	if p.Kind == profile.KindAndroid {
		s.env["ANDROID_ROOT"] = "/system"
		s.env["ANDROID_DATA"] = "/data"
		s.env["EXTERNAL_STORAGE"] = "/sdcard"
		s.cwd = "/"
	} else if home != "/" {
		s.cwd = home
		s.env["PWD"] = home
	}
	if _, ok := fs.Stat(s.cwd); !ok {
		s.cwd = "/"
	}
	fs.SetDynamic("/proc/uptime", func() string {
		up := s.uptime()
		return fmt.Sprintf("%d.%02d %d.%02d\n", int(up.Seconds()), int(up.Milliseconds()/10)%100,
			int(up.Seconds()*3/4), 17)
	})
	return s
}

func (s *Shell) shellPath() string {
	if s.p.Kind == profile.KindAndroid {
		return "/system/bin/sh"
	}
	return "/bin/sh"
}

func (s *Shell) uptime() time.Duration {
	return time.Duration(s.p.UptimeBaseSec)*time.Second + s.now().Sub(s.start)
}

func (s *Shell) Cwd() string { return s.cwd }

func (s *Shell) Prompt() string { return s.renderPrompt(s.p.Shell.Prompt) }

func (s *Shell) renderPrompt(tmpl string) string {
	cwd := s.cwd
	return strings.NewReplacer("{{cwd}}", cwd, "{{user}}", s.p.Shell.User, "{{hostname}}", s.p.Hostname).Replace(tmpl)
}

func (s *Shell) TelnetPrompt() string {
	if s.p.Telnet.Prompt != "" {
		return s.renderPrompt(s.p.Telnet.Prompt)
	}
	return s.Prompt()
}

func (s *Shell) Revealed() []string { return s.revealed }

type simple struct {
	words  []string
	redirs []redir
}

type redir struct {
	op     string
	target string
}

type nodeKind int

const (
	nPipe nodeKind = iota
	nFor
	nIf
	nWhile
)

type node struct {
	kind nodeKind
	pipe []*simple

	v     string
	items []string
	body  []*chain

	branches []branch
	els      []*chain

	cond  []*chain
	until bool
}

type branch struct{ cond, body []*chain }

type link struct {
	n  *node
	op string
}

type chain struct{ links []link }

type parser struct {
	t []tok
	i int
}

func (p *parser) eof() bool { return p.i >= len(p.t) }

func (p *parser) isOp(op string) bool {
	return !p.eof() && p.t[p.i].kind == tOp && p.t[p.i].s == op
}

func (p *parser) kw(w string) bool {
	return !p.eof() && p.t[p.i].kind == tWord && p.t[p.i].s == w
}

func (p *parser) skipSemis() {
	for !p.eof() && p.t[p.i].kind == tOp && (p.t[p.i].s == opSemi || p.t[p.i].s == opBg) {
		p.i++
	}
}

func (p *parser) parseList(stop ...string) []*chain {
	var out []*chain
	for {
		p.skipSemis()
		if p.eof() {
			return out
		}
		for _, w := range stop {
			if p.kw(w) {
				return out
			}
		}
		before := p.i
		out = append(out, p.parseChain())
		if p.i == before {
			p.i++
		}
	}
}

func (p *parser) parseChain() *chain {
	c := &chain{}
	for {
		n := p.parseNode()
		l := link{n: n}
		if !p.eof() && p.t[p.i].kind == tOp {
			switch p.t[p.i].s {
			case opAnd, opOr:
				l.op = p.t[p.i].s
				p.i++
			}
		}
		c.links = append(c.links, l)
		if l.op == "" {
			return c
		}
	}
}

func (p *parser) parseNode() *node {
	switch {
	case p.kw("for"):
		return p.parseFor()
	case p.kw("if"):
		return p.parseIf()
	case p.kw("while"), p.kw("until"):
		return p.parseWhile()
	}
	n := &node{kind: nPipe}
	for {
		n.pipe = append(n.pipe, p.parseSimple())
		if p.isOp(opPipe) {
			p.i++
			continue
		}
		return n
	}
}

func (p *parser) parseSimple() *simple {
	sc := &simple{}
	for !p.eof() {
		t := p.t[p.i]
		if t.kind == tOp {
			if isRedir(t.s) {
				p.i++
				r := redir{op: t.s}
				if t.s != "2>&1" && t.s != ">&2" && !p.eof() && p.t[p.i].kind == tWord {
					r.target = p.t[p.i].s
					p.i++
				}
				sc.redirs = append(sc.redirs, r)
				continue
			}
			break
		}

		if len(sc.words) == 0 {
			switch t.s {
			case "do", "done", "then", "else", "elif", "fi":
				return sc
			}
		}
		sc.words = append(sc.words, t.s)
		p.i++
	}
	return sc
}

func (p *parser) parseFor() *node {
	p.i++
	n := &node{kind: nFor}
	if !p.eof() && p.t[p.i].kind == tWord {
		n.v = p.t[p.i].s
		p.i++
	}
	if p.kw("in") {
		p.i++
		for !p.eof() && p.t[p.i].kind == tWord && !p.kw("do") {
			n.items = append(n.items, p.t[p.i].s)
			p.i++
		}
	}
	p.skipSemis()
	if p.kw("do") {
		p.i++
	}
	n.body = p.parseList("done")
	if p.kw("done") {
		p.i++
	}
	return n
}

func (p *parser) parseWhile() *node {
	n := &node{kind: nWhile, until: p.kw("until")}
	p.i++
	n.cond = p.parseList("do")
	if p.kw("do") {
		p.i++
	}
	n.body = p.parseList("done")
	if p.kw("done") {
		p.i++
	}
	return n
}

func (p *parser) parseIf() *node {
	n := &node{kind: nIf}
	p.i++
	for {
		b := branch{cond: p.parseList("then")}
		if p.kw("then") {
			p.i++
		}
		b.body = p.parseList("elif", "else", "fi")
		n.branches = append(n.branches, b)
		if p.kw("elif") {
			p.i++
			continue
		}
		break
	}
	if p.kw("else") {
		p.i++
		n.els = p.parseList("fi")
	}
	if p.kw("fi") {
		p.i++
	}
	return n
}

func (s *Shell) Exec(line string) Result {
	s.steps, s.depth, s.quit = 0, 0, false
	out := &bytes.Buffer{}
	errb := &bytes.Buffer{}
	s.runString(line, nil, out, errb, false)
	r := Result{Stdout: out.Bytes(), Stderr: errb.Bytes(), Exit: s.lastExit, Quit: s.quit}
	if len(r.Stdout) > maxOutput {
		r.Stdout = r.Stdout[:maxOutput]
	}
	if len(r.Stderr) > maxOutput {
		r.Stderr = r.Stderr[:maxOutput]
	}
	return r
}

func (s *Shell) runString(text string, stdin []byte, out, errb *bytes.Buffer, reveal bool) {
	if reveal {
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || strings.HasPrefix(l, "#") || len(s.revealed) >= maxRevealed {
				continue
			}
			if len(l) > maxScriptLine {
				l = l[:maxScriptLine]
			}
			s.revealed = append(s.revealed, l)
		}
	}
	p := &parser{t: lex(text)}
	for _, c := range p.parseList() {
		s.runChain(c, stdin, out, errb)
		if s.quit || s.steps >= maxSteps {
			return
		}
	}
}

func (s *Shell) runChain(c *chain, stdin []byte, out, errb *bytes.Buffer) {
	prevOp := ""
	for _, l := range c.links {
		skip := (prevOp == opAnd && s.lastExit != 0) || (prevOp == opOr && s.lastExit == 0)
		if !skip {
			s.runNode(l.n, stdin, out, errb)
			if s.quit || s.steps >= maxSteps {
				return
			}
		}
		prevOp = l.op
	}
}

func (s *Shell) runBlock(b []*chain, stdin []byte, out, errb *bytes.Buffer) {
	for _, c := range b {
		s.runChain(c, stdin, out, errb)
		if s.quit || s.steps >= maxSteps {
			return
		}
	}
}

func (s *Shell) runNode(n *node, stdin []byte, out, errb *bytes.Buffer) {
	switch n.kind {
	case nPipe:
		s.runPipe(n.pipe, stdin, out, errb)
	case nFor:
		var items []string
		for _, w := range n.items {
			v, glob := s.expandWord(w)
			if glob {
				if m := s.glob(v); len(m) > 0 {
					items = append(items, m...)
					continue
				}
			}
			items = append(items, strings.Fields(v)...)
		}
		for i, it := range items {
			if i >= maxLoopIter {
				break
			}
			s.env[n.v] = it
			s.runBlock(n.body, stdin, out, errb)
			if s.quit || s.steps >= maxSteps {
				return
			}
		}
	case nIf:
		for _, b := range n.branches {
			s.runBlock(b.cond, stdin, out, errb)
			if s.lastExit == 0 {
				s.runBlock(b.body, stdin, out, errb)
				return
			}
		}
		s.runBlock(n.els, stdin, out, errb)
	case nWhile:

		for i := 0; i < 2; i++ {
			s.runBlock(n.cond, stdin, out, errb)
			if (s.lastExit == 0) == n.until {
				return
			}
			s.runBlock(n.body, stdin, out, errb)
			if s.quit || s.steps >= maxSteps {
				return
			}
		}
	}
}

func (s *Shell) runPipe(cmds []*simple, stdin []byte, out, errb *bytes.Buffer) {
	in := stdin
	for i, c := range cmds {
		last := i == len(cmds)-1
		var o *bytes.Buffer
		if last {
			o = out
		} else {
			o = &bytes.Buffer{}
		}
		s.runSimple(c, in, o, errb)
		if !last {
			in = o.Bytes()
		}
		if s.quit || s.steps >= maxSteps {
			return
		}
	}
}

func (s *Shell) runSimple(c *simple, stdin []byte, out, errb *bytes.Buffer) {
	s.steps++
	if s.steps > maxSteps {
		return
	}

	var argv []string
	for _, w := range c.words {
		v, glob := s.expandWord(w)
		if glob {
			if m := s.glob(v); len(m) > 0 {
				argv = append(argv, m...)
				continue
			}
		}
		argv = append(argv, v)
	}

	for len(argv) > 0 && isAssign(argv[0]) {
		k, v, _ := strings.Cut(argv[0], "=")
		s.env[k] = v
		argv = argv[1:]
	}

	cout, cerr := &bytes.Buffer{}, &bytes.Buffer{}
	var outFile, errFile string
	outAppend, errAppend, errToOut, outToErr := false, false, false, false
	in := stdin
	for _, r := range c.redirs {
		t, _ := s.expandWord(r.target)
		switch r.op {
		case ">", "&>":
			outFile, outAppend = t, false
			if r.op == "&>" {
				errToOut = true
			}
		case ">>", "&>>":
			outFile, outAppend = t, true
			if r.op == "&>>" {
				errToOut = true
			}
		case "2>":
			errFile, errAppend = t, false
		case "2>>":
			errFile, errAppend = t, true
		case "2>&1":
			errToOut = true
		case ">&2":
			outToErr = true
		case "<":
			if data, err := s.fs.ReadFile(s.abs(t)); err == nil {
				in = data
			} else {
				fmt.Fprintf(cerr, "%s\n", s.msg(t, err.Error()))
				s.lastExit = 1
				s.flush(cout, cerr, out, errb, outFile, errFile, outAppend, errAppend, errToOut, outToErr)
				return
			}
		}
	}

	if len(argv) == 0 {
		if len(c.redirs) > 0 {
			s.flush(cout, cerr, out, errb, outFile, errFile, outAppend, errAppend, errToOut, outToErr)
		}
		return
	}
	s.lastExit = s.dispatch(argv, in, cout, cerr)
	s.flush(cout, cerr, out, errb, outFile, errFile, outAppend, errAppend, errToOut, outToErr)
}

func (s *Shell) flush(cout, cerr, out, errb *bytes.Buffer, outFile, errFile string, outApp, errApp, errToOut, outToErr bool) {
	stdout, stderr := cout.Bytes(), cerr.Bytes()
	if errToOut {
		stdout = append(append([]byte(nil), stdout...), stderr...)
		stderr = nil
	}
	if outToErr {
		stderr = append(append([]byte(nil), stderr...), stdout...)
		stdout = nil
	}
	if errFile != "" {
		s.writeTo(errFile, stderr, errApp, errb)
		stderr = nil
	}
	if outFile != "" {
		s.writeTo(outFile, stdout, outApp, errb)
		stdout = nil
	}
	writeCapped(out, stdout)
	writeCapped(errb, stderr)
}

func writeCapped(dst *bytes.Buffer, b []byte) {
	room := maxOutput - dst.Len()
	if room <= 0 || len(b) == 0 {
		return
	}
	if len(b) > room {
		b = b[:room]
	}
	dst.Write(b)
}

func (s *Shell) writeTo(file string, data []byte, appendMode bool, errb *bytes.Buffer) {
	if file == "/dev/null" {
		return
	}
	if err := s.fs.WriteFile(s.abs(file), data, appendMode); err != nil {
		fmt.Fprintf(errb, "%s\n", s.msg("can't create "+file, err.Error()))
		s.lastExit = 1
	}
}

func isAssign(w string) bool {
	k, _, ok := strings.Cut(w, "=")
	if !ok || k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func (s *Shell) abs(p string) string { return vfs.Clean(s.cwd, p) }

func (s *Shell) msg(subject, text string) string {
	prefix := strings.TrimSuffix(fmt.Sprintf(s.p.Shell.NotFound, subject), "not found")
	return prefix + text
}

func (s *Shell) notFound(name string) string { return fmt.Sprintf(s.p.Shell.NotFound, name) }

func (s *Shell) glob(pat string) []string {
	dirPart, filePart := path.Split(pat)
	dir := s.abs(strings.TrimSuffix(dirPart, "/"))
	if dirPart == "" {
		dir = s.cwd
	} else if dirPart == "/" {
		dir = "/"
	}
	if strings.ContainsAny(dirPart, "*?[") {
		return nil
	}
	list, err := s.fs.List(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range list {
		if strings.HasPrefix(e.Name, ".") && !strings.HasPrefix(filePart, ".") {
			continue
		}
		if ok, _ := path.Match(filePart, e.Name); ok {
			out = append(out, dirPart+e.Name)
		}
		if len(out) >= 256 {
			break
		}
	}
	return out
}
