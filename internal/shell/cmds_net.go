package shell

import (
	"net/url"
	"path"
	"strings"
)

func fakeSize(name string) int64 {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h = (h ^ uint32(name[i])) * 16777619
	}
	return int64(2048 + h%60000)
}

func (s *Shell) destination(rawURL, explicit, dir string) string {
	name := explicit
	if name == "" {
		if u, err := url.Parse(rawURL); err == nil {
			name = path.Base(u.Path)
		}
		if name == "" || name == "." || name == "/" {
			name = "index.html"
		}
	}
	if dir != "" && !strings.HasPrefix(name, "/") {
		name = dir + "/" + name
	}
	return s.abs(name)
}

func looksLikeURL(a string) bool {
	return strings.Contains(a, "://") || strings.Contains(a, "/") && !strings.HasPrefix(a, "-") && strings.Contains(a, ".")
}

func cmdWget(c *cctx) int {
	var rawURL, out, dir string
	quiet := false
	args := c.args
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-O" || a == "--output-document") && i+1 < len(args):
			out = args[i+1]
			i++
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			out = a[2:]
		case (a == "-P" || a == "--directory-prefix") && i+1 < len(args):
			dir = args[i+1]
			i++
		case a == "-U" || a == "-T" || a == "-t" || a == "--header" || a == "-Y":
			i++
		case a == "-q" || a == "--quiet":
			quiet = true
		case strings.HasPrefix(a, "-"):
		default:
			if rawURL == "" {
				rawURL = a
			}
		}
	}
	if rawURL == "" {
		c.errorf("wget: missing URL\n")
		return 1
	}
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	if out == "-" {
		return 0
	}
	dst := c.s.destination(rawURL, out, dir)
	if err := c.s.fs.WriteSynthetic(dst, fakeSize(dst)); err != nil {
		c.errorf("wget: can't open '%s': %s\n", path.Base(dst), err.Error())
		return 1
	}
	if !quiet {
		c.printf("Connecting to %s (%s)\nsaving to '%s'\n%-20s 100%% |*******************************| %5d  0:00:00 ETA\n'%s' saved\n",
			host, host, path.Base(dst), path.Base(dst), fakeSize(dst), path.Base(dst))
	}
	return 0
}

func cmdCurl(c *cctx) int {
	var rawURL, out string
	remoteName := false
	args := c.args
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-o" || a == "--output") && i+1 < len(args):
			out = args[i+1]
			i++
		case a == "-O" || a == "--remote-name":
			remoteName = true
		case a == "-A" || a == "-H" || a == "-d" || a == "-X" || a == "-m" || a == "--max-time" || a == "--connect-timeout" || a == "-u":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if rawURL == "" {
				rawURL = a
			}
		}
	}
	if rawURL == "" {
		c.errorf("curl: try 'curl --help' for more information\n")
		return 2
	}
	if out == "" && !remoteName {
		return 0
	}
	dst := c.s.destination(rawURL, out, "")
	if err := c.s.fs.WriteSynthetic(dst, fakeSize(dst)); err != nil {
		c.errorf("curl: (23) Failed writing body\n")
		return 23
	}
	return 0
}

func cmdTftp(c *cctx) int {
	var remote, local string
	get := false
	args := c.args
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-g":
			get = true
		case a == "-r" && i+1 < len(args):
			remote = args[i+1]
			i++
		case a == "-l" && i+1 < len(args):
			local = args[i+1]
			i++
		case a == "-b" && i+1 < len(args):
			i++
		}
	}
	if !get || remote == "" {
		c.errorf("tftp: usage: tftp [-g|-p] -r REMOTE [-l LOCAL] HOST\n")
		return 1
	}
	if local == "" {
		local = path.Base(remote)
	}
	if err := c.s.fs.WriteSynthetic(c.s.abs(local), fakeSize(local)); err != nil {
		return 1
	}
	return 0
}

func cmdFtpget(c *cctx) int {
	var pos []string
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		switch a {
		case "-u", "-p", "-P":
			i++
		default:
			if !strings.HasPrefix(a, "-") {
				pos = append(pos, a)
			}
		}
	}
	if len(pos) < 2 {
		c.errorf("ftpget: usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n")
		return 1
	}
	local := path.Base(pos[len(pos)-1])
	if len(pos) >= 3 {
		local = pos[1]
	}
	if err := c.s.fs.WriteSynthetic(c.s.abs(local), fakeSize(local)); err != nil {
		return 1
	}
	return 0
}
