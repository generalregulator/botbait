package shell

import (
	"sort"
	"strings"
)

func (s *Shell) prop(k string) (string, bool) {
	if s.props != nil {
		if v, ok := s.props[k]; ok {
			return v, true
		}
	}
	v, ok := s.p.Props[k]
	return v, ok
}

func cmdGetprop(c *cctx) int {
	if len(c.args) == 0 {
		keys := make([]string, 0, len(c.s.p.Props)+len(c.s.props))
		seen := map[string]bool{}
		for k := range c.s.p.Props {
			keys, seen[k] = append(keys, k), true
		}
		for k := range c.s.props {
			if !seen[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, _ := c.s.prop(k)
			c.printf("[%s]: [%s]\n", k, v)
		}
		return 0
	}
	v, ok := c.s.prop(c.args[0])
	if !ok && len(c.args) > 1 {
		v = c.args[1]
	}
	c.printf("%s\n", v)
	return 0
}

func cmdSetprop(c *cctx) int {
	if len(c.args) < 2 {
		c.errorf("usage: setprop <key> <value>\n")
		return 1
	}
	if c.s.props == nil {
		c.s.props = map[string]string{}
	}
	if len(c.s.props) < 256 {
		c.s.props[c.args[0]] = c.args[1]
	}
	return 0
}

func cmdPm(c *cctx) int {
	if len(c.args) == 0 {
		c.errorf("usage: pm [subcommand] [options]\n")
		return 1
	}
	switch c.args[0] {
	case "list":
		if len(c.args) > 1 && c.args[1] == "packages" {
			thirdOnly, withPath := false, false
			for _, a := range c.args[2:] {
				switch a {
				case "-3":
					thirdOnly = true
				case "-f":
					withPath = true
				}
			}
			filter := ""
			for _, a := range c.args[2:] {
				if !strings.HasPrefix(a, "-") {
					filter = a
				}
			}
			pkgs := append([]string(nil), c.s.p.Packages...)
			sort.Strings(pkgs)
			for _, p := range pkgs {
				system := strings.HasPrefix(p, "com.android.") || p == "android" || strings.HasPrefix(p, "com.droidlogic")
				if thirdOnly && system || filter != "" && !strings.Contains(p, filter) {
					continue
				}
				if withPath {
					c.printf("package:/system/app/%s/%s.apk=%s\n", p, p, p)
				} else {
					c.printf("package:%s\n", p)
				}
			}
		}
		return 0
	case "path":
		if len(c.args) > 1 {
			for _, p := range c.s.p.Packages {
				if p == c.args[1] {
					c.printf("package:/system/app/%s/%s.apk\n", p, p)
					return 0
				}
			}
		}
		return 1
	case "install", "uninstall", "clear", "grant", "revoke":
		c.printf("Success\n")
		return 0
	case "disable", "disable-user", "enable":
		if len(c.args) > 1 {
			state := "enabled"
			if strings.HasPrefix(c.args[0], "disable") {
				state = "disabled"
			}
			c.printf("Package %s new state: %s\n", c.args[len(c.args)-1], state)
		}
		return 0
	}
	return 0
}

func cmdAm(c *cctx) int {
	if len(c.args) == 0 {
		return 1
	}
	intent := strings.Join(c.args[1:], " ")
	switch c.args[0] {
	case "start", "start-activity":
		c.printf("Starting: Intent { %s }\n", intent)
	case "startservice", "start-service":
		c.printf("Starting service: Intent { %s }\n", intent)
	case "broadcast":
		c.printf("Broadcasting: Intent { %s }\nBroadcast completed: result=0\n", intent)
	}
	return 0
}

func cmdSettings(c *cctx) int {
	if len(c.args) >= 3 && c.args[0] == "get" {
		switch c.args[2] {
		case "adb_enabled", "development_settings_enabled", "install_non_market_apps":
			c.printf("1\n")
		case "device_name":
			c.printf("%s\n", c.s.p.Hostname)
		default:
			c.printf("null\n")
		}
	}
	return 0
}

func cmdDumpsys(c *cctx) int {
	if len(c.args) == 0 {
		c.printf("Currently running services:\n  activity\n  battery\n  connectivity\n  package\n  wifi\n  window\n")
		return 0
	}
	switch c.args[0] {
	case "battery":
		c.printf("Current Battery Service state:\n  AC powered: true\n  USB powered: false\n  Wireless powered: false\n  status: 2\n  health: 2\n  present: true\n  level: 100\n  scale: 100\n")
	default:
		c.printf("Can't find service: %s\n", c.args[0])
	}
	return 0
}

func cmdWm(c *cctx) int {
	if len(c.args) > 0 {
		switch c.args[0] {
		case "size":
			c.printf("Physical size: 1920x1080\n")
		case "density":
			c.printf("Physical density: 240\n")
		}
	}
	return 0
}

func cmdGetenforce(c *cctx) int { c.printf("Permissive\n"); return 0 }
