package shell

import (
	"bytes"
	"crypto/md5"  //nolint:gosec
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/vfs"
)

type cctx struct {
	s    *Shell
	name string
	args []string
	in   []byte
	out  *bytes.Buffer
	err  *bytes.Buffer
}

func (c *cctx) printf(format string, a ...any) { fmt.Fprintf(c.out, format, a...) }
func (c *cctx) errorf(format string, a ...any) { fmt.Fprintf(c.err, format, a...) }

type cmdFunc func(*cctx) int

var alwaysAvailable = map[string]bool{
	"echo": true, "printf": true, "cd": true, "pwd": true, "exit": true, "export": true, "unset": true,
	"set": true, "true": true, "false": true, ":": true, "test": true, "[": true, "eval": true,
	"exec": true, "source": true, ".": true, "type": true, "command": true, "wait": true, "umask": true,
	"trap": true, "alias": true, "ulimit": true, "read": true, "shift": true, "return": true,
	"break": true, "continue": true, "local": true, "readonly": true, "kill": true, "logout": true,
}

var table map[string]cmdFunc

func init() {
	table = map[string]cmdFunc{

		"echo": cmdEcho, "printf": cmdPrintf, "cd": cmdCd, "pwd": cmdPwd, "exit": cmdExit, "logout": cmdExit,
		"export": cmdExport, "unset": cmdUnset, "true": ok, "false": fail, ":": ok,
		"set": ok, "trap": ok, "alias": ok, "ulimit": ok, "umask": ok, "wait": ok, "shift": ok,
		"test": cmdTest, "[": cmdTest, "eval": cmdEval, "exec": cmdExec, "source": cmdSource, ".": cmdSource,
		"type": cmdWhich, "command": cmdCommand, "which": cmdWhich, "read": ok, "local": ok, "readonly": ok,
		"return": ok, "break": ok, "continue": ok,

		"cat": cmdCat, "ls": cmdLs, "mkdir": cmdMkdir, "rm": cmdRm, "rmdir": cmdRmdir, "touch": cmdTouch,
		"cp": cmdCp, "mv": cmdMv, "chmod": cmdChmod, "chown": ok, "chgrp": ok, "ln": cmdLn,
		"head": cmdHead, "tail": cmdTail, "wc": cmdWc, "grep": cmdGrep, "egrep": cmdGrep, "fgrep": cmdGrep,
		"base64": cmdBase64, "md5sum": cmdSum, "sha1sum": cmdSum, "sha256sum": cmdSum,
		"tee": cmdTee, "stat": cmdStat, "dd": cmdDd, "sync": ok, "sleep": ok, "usleep": ok,
		"tar": ok, "gzip": ok, "gunzip": ok, "zcat": ok, "unzip": ok, "insmod": ok, "rmmod": ok,
		"nohup": cmdExec, "su": cmdSu, "sh": cmdSh, "bash": cmdSh, "ash": cmdSh, "busybox": cmdBusybox,
		"toybox": cmdBusybox, "xargs": ok, "awk": ok, "sed": ok, "sort": cmdSort, "uniq": ok, "tr": ok, "cut": ok,
		"find": ok, "du": ok, "hexdump": cmdHexdump, "od": cmdOd, "xxd": cmdXxd, "strings": cmdStrings, "file": cmdFile, "expr": ok, "mknod": ok, "mktemp": cmdMktemp, "renice": ok,
		"nc": ok, "telnet": ok, "telnetd": ok, "iptables": ok, "route": ok, "brctl": ok, "logger": ok,
		"start": ok, "stop": ok, "flash": ok, "cli": ok,

		"uname": cmdUname, "id": cmdID, "whoami": cmdWhoami, "hostname": cmdHostname, "uptime": cmdUptime,
		"date": cmdDate, "ps": cmdPs, "top": cmdTop, "env": cmdEnv, "printenv": cmdEnv, "reboot": cmdReboot,
		"pidof": cmdPidof, "killall": ok, "pkill": ok, "pgrep": cmdPidof, "ping": cmdPing, "kill": ok,
		"dmesg": ok, "lsmod": cmdLsmod, "lsof": ok, "df": ok, "mount": ok, "umount": ok, "free": ok,
		"ifconfig": ok, "netstat": ok, "ip": ok, "nslookup": cmdNslookup, "traceroute": ok,

		"wget": cmdWget, "curl": cmdCurl, "tftp": cmdTftp, "ftpget": cmdFtpget,

		"getprop": cmdGetprop, "setprop": cmdSetprop, "pm": cmdPm, "am": cmdAm, "settings": cmdSettings,
		"input": ok, "dumpsys": cmdDumpsys, "logcat": ok, "wm": cmdWm, "getenforce": cmdGetenforce,
		"setenforce": ok, "service": ok, "content": ok, "log": ok,
	}
}

func ok(*cctx) int   { return 0 }
func fail(*cctx) int { return 1 }

const sysBinDirs = "/system/bin /system/xbin /bin /sbin /usr/bin /usr/sbin /vendor/bin /system/sbin"

func (s *Shell) dispatch(argv []string, in []byte, out, errb *bytes.Buffer) int {
	if strings.Contains(argv[0], "/") {
		return s.runPath(argv, in, out, errb)
	}
	return s.runNamed(argv, in, out, errb, false)
}

func (s *Shell) runNamed(argv []string, in []byte, out, errb *bytes.Buffer, viaBusybox bool) int {
	name := argv[0]
	c := &cctx{s: s, name: name, args: argv[1:], in: in, out: out, err: errb}

	exists := alwaysAvailable[name] || viaBusybox || s.p.HasBin(name) ||
		(name == "busybox" && s.p.Busybox.Present)
	if !exists {
		c.errorf("%s\n", s.notFound(name))
		return 127
	}

	if code, ok := s.canned(argv, out); ok {
		return code
	}
	if fn, ok := table[name]; ok {
		return fn(c)
	}
	return 0
}

func (s *Shell) canned(argv []string, out *bytes.Buffer) (int, bool) {
	if len(s.p.Commands) == 0 {
		return 0, false
	}
	for k := len(argv); k >= 1; k-- {
		if txt, ok := s.p.Commands[strings.Join(argv[:k], " ")]; ok {
			if txt != "" {
				out.WriteString(txt)
				if !strings.HasSuffix(txt, "\n") {
					out.WriteByte('\n')
				}
			}
			return 0, true
		}
	}
	return 0, false
}

func (s *Shell) runPath(argv []string, in []byte, out, errb *bytes.Buffer) int {
	p := s.abs(argv[0])
	info, ok := s.fs.Stat(p)
	switch {
	case !ok:
		fmt.Fprintln(errb, s.notFound(argv[0]))
		return 127
	case info.IsDir:
		fmt.Fprintln(errb, s.msg(argv[0], "Permission denied"))
		return 126
	case info.Mode&0o111 == 0:
		fmt.Fprintln(errb, s.msg(argv[0], "Permission denied"))
		return 126
	}
	if info.Origin == vfs.OriginSeed && strings.Contains(" "+sysBinDirs+" ", " "+path.Dir(p)+" ") {
		argv = append([]string{path.Base(p)}, argv[1:]...)
		return s.runNamed(argv, in, out, errb, true)
	}

	if code, ok := s.canned(append([]string{argv[0]}, argv[1:]...), out); ok {
		return code
	}
	if p != argv[0] {
		if code, ok := s.canned(append([]string{p}, argv[1:]...), out); ok {
			return code
		}
	}

	data, err := s.fs.ReadFile(p)
	if err != nil {
		return 0
	}
	if len(s.p.ExecRules) > 0 {
		ft, sha := payloadstore.Sniff(data), ""
		if s.p.NeedsHash() {
			h := sha256.Sum256(data)
			sha = hex.EncodeToString(h[:])
		}
		for i := range s.p.ExecRules {
			if r := &s.p.ExecRules[i]; r.Matches(p, ft, sha) {
				out.WriteString(r.Stdout)
				errb.WriteString(r.Stderr)
				return r.Exit
			}
		}
	}
	if isScript(data) {
		return s.execScript(string(data), in, out, errb)
	}
	return 0
}

func isScript(data []byte) bool {
	if len(data) == 0 || len(data) > 64<<10 {
		return false
	}
	if bytes.HasPrefix(data, []byte("#!")) {
		return true
	}
	bad := 0
	for _, c := range data {
		if c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c > 0x7e {
			bad++
		}
	}
	return bad*50 < len(data)
}

func (s *Shell) execScript(text string, in []byte, out, errb *bytes.Buffer) int {
	if s.depth >= maxDepth {
		return 0
	}
	s.depth++
	defer func() { s.depth-- }()
	s.lastExit = 0
	savedQuit := s.quit
	s.runString(text, in, out, errb, true)
	if s.depth > 0 {
		s.quit = savedQuit
	}
	return s.lastExit
}

func cmdEcho(c *cctx) int {
	args, nl, esc := c.args, true, true
	for len(args) > 0 {
		a := args[0]
		if len(a) < 2 || a[0] != '-' || strings.Trim(a[1:], "neE") != "" {
			break
		}
		for _, f := range a[1:] {
			switch f {
			case 'n':
				nl = false
			case 'e':
				esc = true
			case 'E':
				esc = false
			}
		}
		args = args[1:]
	}
	text := strings.Join(args, " ")
	var b []byte
	if esc {
		var stop bool
		b, stop = unescape(text)
		if stop {
			nl = false
		}
	} else {
		b = []byte(text)
	}
	c.out.Write(b)
	if nl {
		c.out.WriteByte('\n')
	}
	return 0
}

func unescape(s string) (out []byte, stop bool) {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch != '\\' || i+1 >= len(s) {
			out = append(out, ch)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'a':
			out = append(out, 7)
		case 'b':
			out = append(out, 8)
		case 'c':
			return out, true
		case 'e', 'E':
			out = append(out, 27)
		case 'f':
			out = append(out, 12)
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'v':
			out = append(out, 11)
		case '\\':
			out = append(out, '\\')
		case 'x':
			j, v := i+1, 0
			for ; j < len(s) && j < i+3 && isHex(s[j]); j++ {
				v = v*16 + hexVal(s[j])
			}
			if j == i+1 {
				out = append(out, '\\', 'x')
			} else {
				out = append(out, byte(v))
				i = j - 1
			}
		case '0', '1', '2', '3', '4', '5', '6', '7':

			j, v := i, 0
			if e == '0' {
				j++
			}
			k := 0
			for ; j < len(s) && k < 3 && s[j] >= '0' && s[j] <= '7'; j++ {
				v = v*8 + int(s[j]-'0')
				k++
			}
			out = append(out, byte(v))
			i = j - 1
		default:
			out = append(out, '\\', e)
		}
	}
	return out, false
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return int(c-'A') + 10
}

func cmdPrintf(c *cctx) int {
	if len(c.args) == 0 {
		c.errorf("printf: usage: printf format [arguments]\n")
		return 1
	}
	format, args := c.args[0], c.args[1:]
	for iter := 0; iter < 1000; iter++ {
		used, stop := printfOnce(c.out, format, args)
		if stop || used == 0 || used >= len(args) {
			break
		}
		args = args[used:]
	}
	return 0
}

func printfOnce(out *bytes.Buffer, format string, args []string) (used int, stop bool) {
	next := func() string {
		if used < len(args) {
			used++
			return args[used-1]
		}
		return ""
	}
	for i := 0; i < len(format); i++ {
		ch := format[i]
		switch {
		case ch == '\\':
			j := i + 1
			if j >= len(format) {
				out.WriteByte('\\')
				continue
			}

			end := j + 1
			switch format[j] {
			case 'x':
				for end < len(format) && end < j+3 && isHex(format[end]) {
					end++
				}
			case '0', '1', '2', '3', '4', '5', '6', '7':
				for end < len(format) && end < j+3 && format[end] >= '0' && format[end] <= '7' {
					end++
				}
			}
			b, st := unescape(format[i:end])
			out.Write(b)
			if st {
				return used, true
			}
			i = end - 1
		case ch == '%' && i+1 < len(format):
			i++

			for i < len(format) && strings.IndexByte("-+ #0123456789.", format[i]) >= 0 {
				i++
			}
			if i >= len(format) {
				return used, false
			}
			switch format[i] {
			case '%':
				out.WriteByte('%')
			case 's':
				out.WriteString(next())
			case 'b':
				b, _ := unescape(next())
				out.Write(b)
			case 'c':
				if a := next(); a != "" {
					out.WriteByte(a[0])
				}
			case 'd', 'i', 'u':
				n, _ := strconv.ParseInt(next(), 0, 64)
				out.WriteString(strconv.FormatInt(n, 10))
			case 'x':
				n, _ := strconv.ParseInt(next(), 0, 64)
				out.WriteString(strconv.FormatInt(n, 16))
			case 'X':
				n, _ := strconv.ParseInt(next(), 0, 64)
				out.WriteString(strings.ToUpper(strconv.FormatInt(n, 16)))
			case 'o':
				n, _ := strconv.ParseInt(next(), 0, 64)
				out.WriteString(strconv.FormatInt(n, 8))
			default:
				out.WriteByte('%')
				out.WriteByte(format[i])
			}
		default:
			out.WriteByte(ch)
		}
	}
	return used, false
}

func cmdCd(c *cctx) int {
	target := c.s.env["HOME"]
	if len(c.args) > 0 {
		target = c.args[0]
	}
	if target == "-" {
		target = c.s.cwd
	}
	p := c.s.abs(target)
	info, ok := c.s.fs.Stat(p)
	switch {
	case !ok:
		c.errorf("%s\n", c.s.msg("cd: "+target, "No such file or directory"))
		return 1
	case !info.IsDir:
		c.errorf("%s\n", c.s.msg("cd: "+target, "Not a directory"))
		return 1
	}
	c.s.cwd = p
	c.s.env["PWD"] = p
	return 0
}

func cmdPwd(c *cctx) int { c.printf("%s\n", c.s.cwd); return 0 }

func cmdExit(c *cctx) int {
	code := c.s.lastExit
	if len(c.args) > 0 {
		if n, err := strconv.Atoi(c.args[0]); err == nil {
			code = n & 0xff
		}
	}
	c.s.lastExit = code
	if c.s.depth == 0 {
		c.s.quit = true
	}
	return code
}

func cmdExport(c *cctx) int {
	for _, a := range c.args {
		if k, v, ok := strings.Cut(a, "="); ok && isAssign(a) {
			c.s.env[k] = v
		}
	}
	return 0
}

func cmdUnset(c *cctx) int {
	for _, a := range c.args {
		delete(c.s.env, a)
	}
	return 0
}

func cmdTest(c *cctx) int {
	args := c.args
	if c.name == "[" {
		if len(args) == 0 || args[len(args)-1] != "]" {
			c.errorf("%s\n", c.s.msg("[", "missing ]"))
			return 2
		}
		args = args[:len(args)-1]
	}
	neg := false
	if len(args) > 0 && args[0] == "!" {
		neg, args = true, args[1:]
	}
	res := false
	switch len(args) {
	case 0:
	case 1:
		res = args[0] != ""
	case 2:
		p := c.s.abs(args[1])
		info, exists := c.s.fs.Stat(p)
		switch args[0] {
		case "-e":
			res = exists
		case "-f":
			res = exists && !info.IsDir
		case "-d":
			res = exists && info.IsDir
		case "-x":
			res = exists && info.Mode&0o111 != 0
		case "-r", "-w":
			res = exists
		case "-s":
			res = exists && info.Size > 0
		case "-z":
			res = args[1] == ""
		case "-n":
			res = args[1] != ""
		}
	default:
		switch args[1] {
		case "=", "==":
			res = args[0] == args[2]
		case "!=":
			res = args[0] != args[2]
		case "-eq", "-ne", "-lt", "-gt", "-le", "-ge":
			a, _ := strconv.Atoi(args[0])
			b, _ := strconv.Atoi(args[2])
			res = map[string]bool{"-eq": a == b, "-ne": a != b, "-lt": a < b, "-gt": a > b, "-le": a <= b, "-ge": a >= b}[args[1]]
		}
	}
	if res != neg {
		return 0
	}
	return 1
}

func cmdEval(c *cctx) int {
	return c.s.execScript(strings.Join(c.args, " "), c.in, c.out, c.err)
}

func cmdExec(c *cctx) int {
	if len(c.args) == 0 {
		return 0
	}
	return c.s.dispatch(c.args, c.in, c.out, c.err)
}

func cmdSource(c *cctx) int {
	if len(c.args) == 0 {
		return 0
	}
	data, err := c.s.fs.ReadFile(c.s.abs(c.args[0]))
	if err != nil {
		c.errorf("%s\n", c.s.msg(c.args[0], err.Error()))
		return 1
	}
	return c.s.execScript(string(data), c.in, c.out, c.err)
}

func cmdWhich(c *cctx) int {
	rc := 0
	for _, a := range c.args {
		switch {
		case a == "":
		case alwaysAvailable[a]:
			c.printf("%s\n", a)
		case c.s.p.HasBin(a):
			c.printf("%s/%s\n", firstBinDir(c.s), a)
		case a == "busybox" && c.s.p.Busybox.Present:
			c.printf("%s/busybox\n", map[bool]string{true: "/system/xbin", false: "/bin"}[c.s.p.Kind == "android"])
		default:
			rc = 1
		}
	}
	return rc
}

func firstBinDir(s *Shell) string {
	if s.p.Kind == "android" {
		return "/system/bin"
	}
	return "/bin"
}

func cmdCommand(c *cctx) int {
	if len(c.args) >= 2 && (c.args[0] == "-v" || c.args[0] == "-V") {
		c.args = c.args[1:]
		return cmdWhich(c)
	}
	return cmdExec(c)
}

func cmdSu(c *cctx) int {
	args := c.args
	for len(args) > 0 {
		switch {
		case args[0] == "-c" && len(args) > 1:
			return c.s.execScript(strings.Join(args[1:], " "), c.in, c.out, c.err)
		case strings.HasPrefix(args[0], "-") || allDigits(args[0]) || args[0] == "root" || args[0] == "shell":
			args = args[1:]
		default:
			return c.s.dispatch(args, c.in, c.out, c.err)
		}
	}
	return 0
}

func cmdSh(c *cctx) int {
	args := c.args
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-c" {
		args = args[1:]
	}
	switch {
	case len(args) >= 2 && args[0] == "-c":
		return c.s.execScript(args[1], c.in, c.out, c.err)
	case len(args) >= 1:
		data, err := c.s.fs.ReadFile(c.s.abs(args[0]))
		if err != nil {
			c.errorf("%s\n", c.s.msg(args[0], "No such file or directory"))
			return 127
		}
		if !isScript(data) {
			return 0
		}
		return c.s.execScript(string(data), nil, c.out, c.err)
	case len(c.in) > 0:
		return c.s.execScript(string(c.in), nil, c.out, c.err)
	}
	return 0
}

func cmdBusybox(c *cctx) int {
	p := c.s.p
	if c.name == "toybox" && !p.HasBin("toybox") {
		c.errorf("%s\n", c.s.notFound("toybox"))
		return 127
	}
	if len(c.args) == 0 {
		c.printf("%s\n\nUsage: busybox [function [arguments]...]\n", p.Busybox.Banner)
		return 0
	}
	applet := path.Base(c.args[0])
	if applet == "--list" {
		c.printf("%s\n", strings.Join(p.Busybox.Applets, "\n"))
		return 0
	}
	if !p.HasApplet(applet) {
		c.errorf("%s: applet not found\n", applet)
		return 127
	}
	argv := append([]string{applet}, c.args[1:]...)
	return c.s.runNamed(argv, c.in, c.out, c.err, true)
}

func (c *cctx) readInputs(paths []string) ([]byte, int) {
	if len(paths) == 0 {
		return c.in, 0
	}
	var buf bytes.Buffer
	rc := 0
	for _, a := range paths {
		if a == "-" {
			buf.Write(c.in)
			continue
		}
		data, err := c.s.fs.ReadFile(c.s.abs(a))
		if err != nil {
			c.errorf("%s: %s: %s\n", c.name, a, err.Error())
			rc = 1
			continue
		}
		buf.Write(data)
	}
	return buf.Bytes(), rc
}

func nonFlags(args []string) (flags string, rest []string) {
	for i, a := range args {
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			return
		}
		if len(a) > 1 && a[0] == '-' && !allDigits(a[1:]) {
			flags += a[1:]
		} else {
			rest = append(rest, a)
		}
	}
	return
}

func cmdCat(c *cctx) int {
	_, rest := nonFlags(c.args)
	data, rc := c.readInputs(rest)
	c.out.Write(data)
	return rc
}

func cmdLs(c *cctx) int {
	flags, rest := nonFlags(c.args)
	long, all := strings.Contains(flags, "l"), strings.Contains(flags, "a") || strings.Contains(flags, "A")
	if len(rest) == 0 {
		rest = []string{"."}
	}
	rc := 0
	for i, a := range rest {
		p := c.s.abs(a)
		info, exists := c.s.fs.Stat(p)
		if !exists {
			c.errorf("ls: %s: No such file or directory\n", a)
			rc = 1
			continue
		}
		var entries []vfs.Info
		if info.IsDir && !strings.Contains(flags, "d") {
			entries, _ = c.s.fs.List(p)
			if len(rest) > 1 {
				if i > 0 {
					c.printf("\n")
				}
				c.printf("%s:\n", a)
			}
		} else {
			entries = []vfs.Info{info}
			entries[0].Name = a
		}
		if long {
			c.printf("total %d\n", len(entries)*4)
		}
		for _, e := range entries {
			if !all && strings.HasPrefix(e.Name, ".") {
				continue
			}
			if long {
				c.printf("%s\n", c.s.longLine(e))
			} else {
				c.printf("%s\n", e.Name)
			}
		}
	}
	return rc
}

func (s *Shell) longLine(e vfs.Info) string {
	perm := modeString(e.Mode, e.IsDir)
	if s.p.Kind == "android" {
		return fmt.Sprintf("%s root     %-8s %8d %s %s", perm, "root", e.Size, e.MTime.Format("2006-01-02 15:04"), e.Name)
	}
	return fmt.Sprintf("%s    1 root     root     %8d %s %s", perm, e.Size, e.MTime.Format("Jan _2 15:04"), e.Name)
}

func modeString(m uint32, dir bool) string {
	b := []byte("----------")
	if dir {
		b[0] = 'd'
	}
	for i, ch := range "rwxrwxrwx" {
		if m&(1<<uint(8-i)) != 0 {
			b[i+1] = byte(ch)
		}
	}
	return string(b)
}

func cmdMkdir(c *cctx) int {
	flags, rest := nonFlags(c.args)
	rc := 0
	for _, a := range rest {
		if err := c.s.fs.Mkdir(c.s.abs(a), strings.Contains(flags, "p")); err != nil {
			c.errorf("mkdir: can't create directory '%s': %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdRm(c *cctx) int {
	flags, rest := nonFlags(c.args)
	force := strings.Contains(flags, "f")
	rec := strings.ContainsAny(flags, "rR")
	rc := 0
	for _, a := range rest {
		p := c.s.abs(a)
		if p == "/" {
			continue
		}
		if info, ok := c.s.fs.Stat(p); ok && info.IsDir && !rec {
			c.errorf("rm: '%s' is a directory\n", a)
			rc = 1
			continue
		}
		if err := c.s.fs.Remove(p, rec); err != nil && !force {
			c.errorf("rm: can't remove '%s': %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdRmdir(c *cctx) int {
	rc := 0
	for _, a := range c.args {
		if err := c.s.fs.Remove(c.s.abs(a), false); err != nil {
			c.errorf("rmdir: '%s': %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdTouch(c *cctx) int {
	_, rest := nonFlags(c.args)
	rc := 0
	for _, a := range rest {
		p := c.s.abs(a)
		if _, ok := c.s.fs.Stat(p); ok {
			continue
		}
		if err := c.s.fs.WriteFile(p, nil, false); err != nil {
			c.errorf("touch: %s: %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdCp(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) < 2 {
		c.errorf("cp: missing file operand\n")
		return 1
	}
	dst := c.s.abs(rest[len(rest)-1])
	rc := 0
	for _, a := range rest[:len(rest)-1] {
		if err := c.s.fs.Copy(c.s.abs(a), dst); err != nil {
			c.errorf("cp: can't stat '%s': %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdMv(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) < 2 {
		c.errorf("mv: missing file operand\n")
		return 1
	}
	dst := c.s.abs(rest[len(rest)-1])
	rc := 0
	for _, a := range rest[:len(rest)-1] {
		if err := c.s.fs.Rename(c.s.abs(a), dst); err != nil {
			c.errorf("mv: can't rename '%s': %s\n", a, err.Error())
			rc = 1
		}
	}
	return rc
}

func cmdLn(c *cctx) int {
	flags, rest := nonFlags(c.args)
	if len(rest) < 2 {
		return 1
	}
	if strings.Contains(flags, "s") {
		return 0
	}
	if err := c.s.fs.Copy(c.s.abs(rest[0]), c.s.abs(rest[1])); err != nil {
		c.errorf("ln: %s: %s\n", rest[0], err.Error())
		return 1
	}
	return 0
}

func cmdChmod(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) < 2 {
		c.errorf("chmod: missing operand\n")
		return 1
	}
	mode := rest[0]
	rc := 0
	for _, a := range rest[1:] {
		p := c.s.abs(a)
		info, ok := c.s.fs.Stat(p)
		if !ok {
			c.errorf("chmod: %s: No such file or directory\n", a)
			rc = 1
			continue
		}
		nm := info.Mode
		if v, err := strconv.ParseUint(mode, 8, 32); err == nil {
			nm = uint32(v) & 0o7777
		} else if m, ok := symbolicMode(mode, nm); ok {
			nm = m
		} else {
			c.errorf("chmod: bad mode '%s'\n", mode)
			return 1
		}
		_ = c.s.fs.Chmod(p, nm)
	}
	return rc
}

var symRe = regexp.MustCompile(`^([ugoa]*)([+-=])([rwx]+)$`)

func symbolicMode(spec string, cur uint32) (uint32, bool) {
	for _, part := range strings.Split(spec, ",") {
		m := symRe.FindStringSubmatch(part)
		if m == nil {
			return cur, false
		}
		who, op, perms := m[1], m[2], m[3]
		if who == "" || strings.Contains(who, "a") {
			who = "ugo"
		}
		var bits uint32
		for _, w := range who {
			shift := map[rune]uint{'u': 6, 'g': 3, 'o': 0}[w]
			for _, p := range perms {
				bits |= map[rune]uint32{'r': 4, 'w': 2, 'x': 1}[p] << shift
			}
		}
		switch op {
		case "+":
			cur |= bits
		case "-":
			cur &^= bits
		case "=":
			cur = bits
		}
	}
	return cur, true
}

func cmdHead(c *cctx) int { return headTail(c, true) }
func cmdTail(c *cctx) int { return headTail(c, false) }

func headTail(c *cctx, head bool) int {
	n, bytesN := 10, -1
	var files []string
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		switch {
		case a == "-n" && i+1 < len(c.args):
			n, _ = strconv.Atoi(c.args[i+1])
			i++
		case a == "-c" && i+1 < len(c.args):
			bytesN, _ = strconv.Atoi(c.args[i+1])
			i++
		case strings.HasPrefix(a, "-c") && len(a) > 2 && allDigits(a[2:]):
			bytesN, _ = strconv.Atoi(a[2:])
		case strings.HasPrefix(a, "-n") && len(a) > 2 && allDigits(a[2:]):
			n, _ = strconv.Atoi(a[2:])
		case len(a) > 1 && a[0] == '-' && allDigits(a[1:]):
			n, _ = strconv.Atoi(a[1:])
		case strings.HasPrefix(a, "-"):
		default:
			files = append(files, a)
		}
	}
	data, rc := c.readInputs(files)
	if bytesN >= 0 {
		switch {
		case bytesN >= len(data):
		case head:
			data = data[:bytesN]
		default:
			data = data[len(data)-bytesN:]
		}
		c.out.Write(data)
		return rc
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if n < 0 {
		n = 0
	}
	if head {
		if n < len(lines) {
			lines = lines[:n]
		}
	} else if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		c.out.Write(l)
	}
	return rc
}

func cmdWc(c *cctx) int {
	flags, rest := nonFlags(c.args)
	data, rc := c.readInputs(rest)
	lines := bytes.Count(data, []byte("\n"))
	words := len(bytes.Fields(data))
	switch {
	case strings.Contains(flags, "l"):
		c.printf("%d\n", lines)
	case strings.Contains(flags, "c"):
		c.printf("%d\n", len(data))
	case strings.Contains(flags, "w"):
		c.printf("%d\n", words)
	default:
		c.printf("%7d %7d %7d\n", lines, words, len(data))
	}
	return rc
}

func cmdGrep(c *cctx) int {
	var pat string
	var files []string
	invert, icase, count, quiet, havePat := false, false, false, false, false
	for _, a := range c.args {
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, f := range a[1:] {
				switch f {
				case 'v':
					invert = true
				case 'i':
					icase = true
				case 'c':
					count = true
				case 'q':
					quiet = true
				}
			}
			continue
		}
		if !havePat {
			pat, havePat = a, true
		} else {
			files = append(files, a)
		}
	}
	if !havePat {
		return 2
	}
	if c.name == "fgrep" {
		pat = regexp.QuoteMeta(pat)
	}
	if icase {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(pat))
	}
	data, _ := c.readInputs(files)
	matched := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if re.Match(line) != invert {
			matched++
			if !count && !quiet {
				c.out.Write(line)
				c.out.WriteByte('\n')
			}
		}
	}
	if count {
		c.printf("%d\n", matched)
	}
	if matched == 0 {
		return 1
	}
	return 0
}

func cmdSort(c *cctx) int {
	_, rest := nonFlags(c.args)
	data, rc := c.readInputs(rest)
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	sort.Strings(lines)
	for _, l := range lines {
		if l != "" {
			c.printf("%s\n", l)
		}
	}
	return rc
}

func cmdBase64(c *cctx) int {
	flags, rest := nonFlags(c.args)
	data, rc := c.readInputs(rest)
	if strings.ContainsAny(flags, "dD") {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' {
				return -1
			}
			return r
		}, string(data))
		dec, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			dec, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "="))
		}
		if err != nil {
			c.errorf("base64: invalid input\n")
			return 1
		}
		c.out.Write(dec)
		return rc
	}
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		c.printf("%s\n", enc[:76])
		enc = enc[76:]
	}
	c.printf("%s\n", enc)
	return rc
}

func cmdSum(c *cctx) int {
	_, rest := nonFlags(c.args)
	sum := func(b []byte) string {
		switch c.name {
		case "md5sum":
			h := md5.Sum(b) //nolint:gosec
			return hex.EncodeToString(h[:])
		case "sha1sum":
			h := sha1.Sum(b) //nolint:gosec
			return hex.EncodeToString(h[:])
		}
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	if len(rest) == 0 {
		c.printf("%s  -\n", sum(c.in))
		return 0
	}
	rc := 0
	for _, a := range rest {
		data, err := c.s.fs.ReadFile(c.s.abs(a))
		if err != nil {
			c.errorf("%s: %s: %s\n", c.name, a, err.Error())
			rc = 1
			continue
		}
		c.printf("%s  %s\n", sum(data), a)
	}
	return rc
}

func cmdTee(c *cctx) int {
	flags, rest := nonFlags(c.args)
	c.out.Write(c.in)
	for _, a := range rest {
		_ = c.s.fs.WriteFile(c.s.abs(a), c.in, strings.Contains(flags, "a"))
	}
	return 0
}

func cmdStat(c *cctx) int {
	_, rest := nonFlags(c.args)
	rc := 0
	for _, a := range rest {
		info, ok := c.s.fs.Stat(c.s.abs(a))
		if !ok {
			c.errorf("stat: can't stat '%s': No such file or directory\n", a)
			rc = 1
			continue
		}
		c.printf("  File: %s\n  Size: %d\n  Mode: (%04o/%s)\n", a, info.Size, info.Mode, modeString(info.Mode, info.IsDir))
	}
	return rc
}

func cmdMktemp(c *cctx) int {
	p := fmt.Sprintf("/data/local/tmp/tmp.%06d", c.s.steps*7919%1000000)
	if c.s.p.Kind != "android" {
		p = fmt.Sprintf("/tmp/tmp.%06d", c.s.steps*7919%1000000)
	}
	if err := c.s.fs.WriteFile(p, nil, false); err != nil {
		return 1
	}
	c.printf("%s\n", p)
	return 0
}
