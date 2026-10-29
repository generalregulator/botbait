package vfs

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/generalregulator/botbait/internal/profile"
)

func newFS(t *testing.T, name string) (*FS, *profile.Profile) {
	t.Helper()
	p, err := profile.Load(name, "seed")
	if err != nil {
		t.Fatal(err)
	}
	return NewBase(p).New(DefaultLimits), p
}

func TestSkeletonFromProfile(t *testing.T) {
	f, p := newFS(t, "android-tvbox")
	for _, path := range []string{"/system/build.prop", "/proc/cpuinfo", "/data/local/tmp", "/system/bin/getprop", "/system/xbin/busybox", "/dev/null"} {
		if _, ok := f.Stat(path); !ok {
			t.Errorf("%s missing", path)
		}
	}
	bp, err := f.ReadFile("/system/build.prop")
	if err != nil || !strings.Contains(string(bp), "ro.product.model=MXQ-4K") || strings.Contains(string(bp), "persist.") {
		t.Fatalf("build.prop wrong: %v %q", err, bp)
	}
	if !strings.Contains(string(bp), "ro.serialno="+p.Props["ro.serialno"]) {
		t.Fatal("build.prop must carry the seeded serial")
	}
	list, err := f.List("/data/local")
	if err != nil || len(list) != 1 || list[0].Name != "tmp" {
		t.Fatalf("list: %v %v", list, err)
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	p, _ := profile.Load("android-tvbox", "s")
	base := NewBase(p)
	a, b := base.New(DefaultLimits), base.New(DefaultLimits)
	if err := a.WriteFile("/data/local/tmp/x", []byte("hello"), false); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Stat("/data/local/tmp/x"); ok {
		t.Fatal("write in one session leaked into another")
	}
	if err := a.WriteFile("/system/etc/hosts", []byte("1.2.3.4 evil\n"), true); err != nil {
		t.Fatal(err)
	}
	orig, _ := b.ReadFile("/system/etc/hosts")
	if strings.Contains(string(orig), "evil") {
		t.Fatal("base mutated")
	}
	mine, _ := a.ReadFile("/system/etc/hosts")
	if !strings.HasPrefix(string(mine), "127.0.0.1 localhost\n") || !strings.Contains(string(mine), "evil") {
		t.Fatalf("append to seed file lost seed content: %q", mine)
	}
}

func TestAppendAssemblesDropper(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	parts := [][]byte{[]byte("\x7fELF"), {1, 2, 3}, bytes.Repeat([]byte{0xAA}, 100)}
	for i, part := range parts {
		if err := f.WriteFile("/data/local/tmp/.a", part, i > 0); err != nil {
			t.Fatal(err)
		}
	}
	got := f.Created()
	if len(got) != 1 || !bytes.Equal(got[0].Data, bytes.Join(parts, nil)) || got[0].Path != "/data/local/tmp/.a" {
		t.Fatalf("created: %+v", got)
	}
}

func TestDeletedDropperIsStillHarvested(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	_ = f.WriteFile("/tmp/x", []byte("payload-bytes"), false)
	_ = f.Mkdir("/tmp", true)
	_ = f.WriteFile("/data/local/tmp/y", []byte("second-stage"), false)
	if err := f.Remove("/data/local/tmp/y", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Stat("/data/local/tmp/y"); ok {
		t.Fatal("file should be gone for the attacker")
	}
	var found bool
	for _, c := range f.Created() {
		if string(c.Data) == "second-stage" {
			found = true
		}
	}
	if !found {
		t.Fatal("self-deleting dropper must still be captured")
	}
}

func TestTruncationArchivesPreviousStage(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	_ = f.WriteFile("/data/local/tmp/s", []byte("stage-one"), false)
	_ = f.WriteFile("/data/local/tmp/s", []byte("stage-two"), false)
	var one, two bool
	for _, c := range f.Created() {
		one = one || string(c.Data) == "stage-one"
		two = two || string(c.Data) == "stage-two"
	}
	if !one || !two {
		t.Fatalf("both stages must be harvested: one=%v two=%v", one, two)
	}
}

func TestTamperingWithSeedFilesIsNotHarvested(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	_ = f.WriteFile("/system/etc/hosts", []byte("0.0.0.0 av.example\n"), true)
	_ = f.WriteFile("/default.prop", []byte("x=y\n"), false)
	if got := f.Created(); len(got) != 0 {
		t.Fatalf("seed-file edits must not be reported as samples: %+v", got)
	}
}

func TestProcSysDevWritesAreSwallowed(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	for _, p := range []string{"/proc/sys/vm/drop_caches", "/sys/class/x", "/dev/null", "/dev/tcp/1.2.3.4/80"} {
		if err := f.WriteFile(p, []byte("1"), false); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if len(f.Created()) != 0 {
		t.Fatal("nothing should have been kept")
	}
	if b, _ := f.ReadFile("/dev/null"); len(b) != 0 {
		t.Fatal("/dev/null must stay empty")
	}
}

func TestLimitsStopDoublingAndNodeFlood(t *testing.T) {
	p, _ := profile.Load("android-tvbox", "s")
	f := NewBase(p).New(Limits{MaxFileBytes: 1024, MaxTotalBytes: 4096, MaxNodes: 5})
	_ = f.WriteFile("/data/local/tmp/a", bytes.Repeat([]byte("A"), 600), false)

	var err error
	for i := 0; i < 50 && err == nil; i++ {
		var data []byte
		data, _ = f.ReadFile("/data/local/tmp/a")
		err = f.WriteFile("/data/local/tmp/a", data, true)
	}
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("want ErrNoSpace, got %v", err)
	}
	var nodeErr error
	for i := 0; i < 20 && nodeErr == nil; i++ {
		nodeErr = f.WriteFile("/data/local/tmp/n"+string(rune('a'+i)), []byte("x"), false)
	}
	if !errors.Is(nodeErr, ErrNoSpace) {
		t.Fatalf("node cap not enforced: %v", nodeErr)
	}
}

func TestMkdirRenameCopyChmod(t *testing.T) {
	f, _ := newFS(t, "router-busybox")
	if err := f.Mkdir("/tmp/a/b", false); !errors.Is(err, ErrNotExist) {
		t.Fatalf("mkdir without -p: %v", err)
	}
	if err := f.Mkdir("/tmp/a/b", true); err != nil {
		t.Fatal(err)
	}
	_ = f.WriteFile("/tmp/a/b/f", []byte("data"), false)
	if err := f.Rename("/tmp/a", "/tmp/z"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Stat("/tmp/a/b/f"); ok {
		t.Fatal("old path still exists")
	}
	if b, err := f.ReadFile("/tmp/z/b/f"); err != nil || string(b) != "data" {
		t.Fatalf("moved tree: %q %v", b, err)
	}
	if err := f.Copy("/tmp/z/b/f", "/tmp"); err != nil {
		t.Fatal(err)
	}
	if b, _ := f.ReadFile("/tmp/f"); string(b) != "data" {
		t.Fatal("copy into directory")
	}
	if err := f.Chmod("/bin/ls", 0o700); err != nil {
		t.Fatal(err)
	}
	if info, _ := f.Stat("/bin/ls"); info.Mode != 0o700 {
		t.Fatalf("mode %o", info.Mode)
	}
	b2 := NewBase(mustProfile(t, "router-busybox")).New(DefaultLimits)
	if info, _ := b2.Stat("/bin/ls"); info.Mode != 0o755 {
		t.Fatal("chmod leaked into the shared base")
	}
}

func mustProfile(t *testing.T, n string) *profile.Profile {
	p, err := profile.Load(n, "seed")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRemoveSeedAndNonEmpty(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	if err := f.Remove("/data/local", false); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("non-empty dir: %v", err)
	}
	if err := f.Remove("/system/etc/hosts", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Stat("/system/etc/hosts"); ok {
		t.Fatal("seed file should be hidden after rm")
	}
	if err := f.Remove("/system/etc/hosts", false); !errors.Is(err, ErrNotExist) {
		t.Fatalf("second rm: %v", err)
	}
	if err := f.Remove("/data", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Stat("/data/local/tmp"); ok {
		t.Fatal("recursive removal left children visible")
	}
}

func TestDynamicAndPushedAndSynthetic(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	f.SetDynamic("/proc/uptime", func() string { return "123.45 100.00\n" })
	if b, err := f.ReadFile("/proc/uptime"); err != nil || string(b) != "123.45 100.00\n" {
		t.Fatalf("dynamic: %q %v", b, err)
	}
	if err := f.AddPushed("/data/local/tmp/bot", 0o755, 123456, nil); err != nil {
		t.Fatal(err)
	}
	if info, _ := f.Stat("/data/local/tmp/bot"); info.Size != 123456 || info.Mode != 0o755 {
		t.Fatalf("pushed info: %+v", info)
	}
	if err := f.WriteSynthetic("/data/local/tmp/x.sh", 2048); err != nil {
		t.Fatal(err)
	}
	if len(f.Created()) != 0 {
		t.Fatal("pushed/synthetic files must not be harvested from the VFS")
	}
}

func TestClean(t *testing.T) {
	for _, c := range []struct{ cwd, in, want string }{
		{"/data/local/tmp", "x", "/data/local/tmp/x"},
		{"/data/local/tmp", "../../etc", "/data/etc"},
		{"/", "..", "/"},
		{"/a", "/b/../c", "/c"},
		{"/a", "", "/a"},
	} {
		if got := Clean(c.cwd, c.in); got != c.want {
			t.Errorf("Clean(%q,%q)=%q want %q", c.cwd, c.in, got, c.want)
		}
	}
}

func TestDeviceBinariesReadAsELFForTheProfileArchitecture(t *testing.T) {
	for _, c := range []struct {
		profile, bin string
		class, data  byte
		machine      uint16
	}{
		{"android-tvbox", "/system/bin/ls", 1, 1, 40},
		{"router-busybox", "/bin/busybox", 1, 2, 8},
	} {
		f, _ := newFS(t, c.profile)
		b, err := f.ReadFile(c.bin)
		if err != nil || len(b) < 52 || string(b[:4]) != "\x7fELF" {
			t.Fatalf("%s: %v % x", c.bin, err, b[:min(len(b), 8)])
		}
		if b[4] != c.class || b[5] != c.data {
			t.Errorf("%s: class/data = %d/%d", c.profile, b[4], b[5])
		}
		var machine uint16
		if c.data == 2 {
			machine = uint16(b[18])<<8 | uint16(b[19])
		} else {
			machine = uint16(b[19])<<8 | uint16(b[18])
		}
		if machine != c.machine {
			t.Errorf("%s: e_machine = %d, want %d", c.profile, machine, c.machine)
		}
		if info, _ := f.Stat(c.bin); info.Size != int64(len(b)) {
			t.Errorf("%s: stat size %d != content %d", c.bin, info.Size, len(b))
		}

		f2, _ := newFS(t, c.profile)
		if b2, _ := f2.ReadFile(c.bin); !bytes.Equal(b, b2) {
			t.Errorf("%s: content differs between sessions", c.bin)
		}

		if o, _ := f.ReadFile("/proc/self/exe"); bytes.Equal(o, b) {
			t.Errorf("distinct binaries must not be identical")
		}
	}
}

func TestCopyOfDeviceBinaryIsNotASample(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	if err := f.Copy("/system/bin/ls", "/data/local/tmp/dvrHelper"); err != nil {
		t.Fatal(err)
	}
	orig, _ := f.ReadFile("/system/bin/ls")
	if cp, _ := f.ReadFile("/data/local/tmp/dvrHelper"); !bytes.Equal(cp, orig) {
		t.Fatal("the copy must read like the original")
	}
	if len(f.Created()) != 0 {
		t.Fatalf("a copy of a device binary must not be harvested: %+v", f.Created())
	}

	if err := f.WriteFile("/data/local/tmp/dvrHelper", nil, false); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile("/data/local/tmp/dvrHelper", []byte("\x7fELFreal"), true); err != nil {
		t.Fatal(err)
	}
	c := f.Created()
	if len(c) != 1 || string(c[0].Data) != "\x7fELFreal" {
		t.Fatalf("harvest after truncate+append: %+v", c)
	}
}

func TestPushedFileReadsBackFromLoader(t *testing.T) {
	f, _ := newFS(t, "android-tvbox")
	content := []byte("\x7fELF-pushed-bytes")
	calls := 0
	if err := f.AddPushed("/data/local/tmp/bot", 0o755, int64(len(content)), func() ([]byte, error) { calls++; return content, nil }); err != nil {
		t.Fatal(err)
	}
	got, err := f.ReadFile("/data/local/tmp/bot")
	if err != nil || !bytes.Equal(got, content) || calls != 1 {
		t.Fatalf("read back: %q %v calls=%d", got, err, calls)
	}
	if len(f.Created()) != 0 {
		t.Fatal("pushed content is already in the store and must not be harvested again")
	}
}

func TestMiraiEchoLoaderFlowYieldsOnlyTheRealPayload(t *testing.T) {
	f, _ := newFS(t, "router-busybox")
	img, _ := f.ReadFile("/bin/echo")

	if err := f.WriteFile("/tmp/x", img, false); err != nil {
		t.Fatal(err)
	}
	if len(f.Created()) != 0 {
		t.Fatalf("a verbatim copy of a device binary is not a sample: %d", len(f.Created()))
	}
	if err := f.WriteFile("/tmp/x", nil, false); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile("/tmp/x", []byte("\x7fELFreal"), true); err != nil {
		t.Fatal(err)
	}
	c := f.Created()
	if len(c) != 1 || string(c[0].Data) != "\x7fELFreal" {
		t.Fatalf("harvest: %+v", c)
	}
}
