package shell

import (
	"fmt"
	"sort"
	"strings"

	"github.com/generalregulator/botbait/internal/profile"
)

func (s *Shell) nodeName() string {
	if h, ok := s.p.Commands["hostname"]; ok {
		return strings.TrimSpace(h)
	}
	return s.p.Hostname
}

func cmdUname(c *cctx) int {
	k := c.s.p.Kernel
	flags := ""
	for _, a := range c.args {
		if strings.HasPrefix(a, "-") {
			flags += a[1:]
		}
	}
	if flags == "" {
		flags = "s"
	}
	var parts []string
	has := func(f string) bool { return strings.Contains(flags, f) }
	if has("a") {
		parts = []string{k.Sysname, c.s.nodeName(), k.Release, k.Version, k.Machine}
		if c.s.p.Kind == profile.KindAndroid {
			parts = append(parts, "Android")
		}
	} else {
		if has("s") {
			parts = append(parts, k.Sysname)
		}
		if has("n") {
			parts = append(parts, c.s.nodeName())
		}
		if has("r") {
			parts = append(parts, k.Release)
		}
		if has("v") {
			parts = append(parts, k.Version)
		}
		if has("m") || has("p") || has("i") {
			parts = append(parts, k.Machine)
		}
		if has("o") {
			parts = append(parts, k.OS)
		}
	}
	c.printf("%s\n", strings.Join(parts, " "))
	return 0
}

func cmdID(c *cctx) int {
	u := c.s.p.Shell
	if c.s.p.Kind == profile.KindAndroid {
		c.printf("uid=%d(%s) gid=%d(%s) groups=%d(%s),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats) context=u:r:su:s0\n",
			u.UID, u.User, u.UID, u.User, u.UID, u.User)
		return 0
	}
	c.printf("uid=%d(%s) gid=%d(%s)\n", u.UID, u.User, u.UID, u.User)
	return 0
}

func cmdWhoami(c *cctx) int { c.printf("%s\n", c.s.p.Shell.User); return 0 }

func cmdHostname(c *cctx) int {
	if len(c.args) > 0 && !strings.HasPrefix(c.args[0], "-") {
		return 0
	}
	c.printf("%s\n", c.s.nodeName())
	return 0
}

func cmdUptime(c *cctx) int {
	up := c.s.uptime()
	d := int(up.Hours()) / 24
	h := int(up.Hours()) % 24
	m := int(up.Minutes()) % 60
	sec := int(up.Seconds()) % 60
	if c.s.p.Kind == profile.KindAndroid {
		c.printf("up time: %d days, %02d:%02d:%02d, idle time: %d days, %02d:%02d:%02d, sleep time: 0 days, 00:00:00\n",
			d, h, m, sec, d*3/4, (h+3)%24, (m+11)%60, (sec+7)%60)
		return 0
	}
	now := c.s.now().UTC()
	c.printf(" %s up %d days, %2d:%02d,  load average: 0.08, 0.05, 0.01\n", now.Format("15:04:05"), d, h, m)
	return 0
}

func cmdDate(c *cctx) int {
	c.printf("%s\n", c.s.now().UTC().Format("Mon Jan _2 15:04:05 MST 2006"))
	return 0
}

func cmdPs(c *cctx) int {
	procs := c.s.p.Processes
	if c.s.p.Kind == profile.KindAndroid {
		c.printf("USER      PID   PPID  VSIZE  RSS   WCHAN            PC  NAME\n")
		for _, p := range procs {
			c.printf("%-9s %-5d %-5d %-6d %-5d %-9s %08x S %s\n", p.User, p.PID, p.PPID, p.VSize, p.RSS, "SyS_epoll", 0, p.Name)
		}
		return 0
	}
	c.printf("  PID USER       VSZ STAT COMMAND\n")
	for _, p := range procs {
		c.printf("%5d %-8s %5d S    %s\n", p.PID, p.User, p.VSize, p.Name)
	}
	return 0
}

func cmdTop(c *cctx) int {
	if txt, ok := c.s.p.Commands["top"]; ok {
		c.printf("%s\n", txt)
		return 0
	}
	c.printf("Mem: 850420K used, 162764K free, 0K shrd, 32184K buff, 391288K cached\nCPU:  3.1%% usr  1.9%% sys  0.0%% nic 94.7%% idle  0.0%% io  0.0%% irq  0.3%% sirq\nLoad average: 0.52 0.47 0.43 1/412 6188\n")
	cmdPs(c)
	return 0
}

func cmdEnv(c *cctx) int {
	keys := make([]string, 0, len(c.s.env))
	for k := range c.s.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c.printf("%s=%s\n", k, c.s.env[k])
	}
	return 0
}

func cmdReboot(c *cctx) int {

	if c.s.depth == 0 {
		c.s.quit = true
	}
	return 0
}

func cmdPidof(c *cctx) int {
	var pids []string
	for _, a := range c.args {
		for _, p := range c.s.p.Processes {
			base := p.Name
			if i := strings.LastIndexByte(base, '/'); i >= 0 {
				base = base[i+1:]
			}
			if base == a {
				pids = append(pids, fmt.Sprint(p.PID))
			}
		}
	}
	if len(pids) == 0 {
		return 1
	}
	c.printf("%s\n", strings.Join(pids, " "))
	return 0
}

func cmdPing(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) == 0 {
		c.errorf("ping: usage: ping [OPTIONS] HOST\n")
		return 1
	}
	host := rest[len(rest)-1]
	c.printf("PING %s (%s): 56 data bytes\n64 bytes from %s: seq=0 ttl=57 time=12.4 ms\n64 bytes from %s: seq=1 ttl=57 time=11.9 ms\n\n--- %s ping statistics ---\n2 packets transmitted, 2 packets received, 0%% packet loss\n",
		host, host, host, host, host)
	return 0
}

func cmdNslookup(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) == 0 {
		return 1
	}
	c.printf("Server:    8.8.8.8\nAddress 1: 8.8.8.8 dns.google\n\nName:      %s\nAddress 1: 93.184.216.34\n", rest[0])
	return 0
}

func cmdLsmod(c *cctx) int {
	c.printf("Module                  Size  Used by\n")
	return 0
}
