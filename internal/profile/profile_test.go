package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinsLoadAndValidate(t *testing.T) {
	names := Builtins()
	if len(names) < 2 {
		t.Fatalf("expected at least two built-in profiles, got %v", names)
	}
	for _, n := range names {
		p, err := Load(n, "seed-1")
		if err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if strings.Contains(p.ADBBanner(), "{{") || strings.Contains(p.Shell.Prompt, "{{hostname}}") {
			t.Errorf("%s: unresolved placeholders in banner/prompt", n)
		}
		for k, v := range p.Props {
			if strings.Contains(v, "{{") {
				t.Errorf("%s: prop %s unresolved: %q", n, k, v)
			}
		}
		for k, v := range p.Commands {
			if strings.Contains(v, "{{") {
				t.Errorf("%s: command %q unresolved", n, k)
			}
		}
	}
}

func TestSeedChangesIdentifiersDeterministically(t *testing.T) {
	a1, _ := Load("android-tvbox", "alpha")
	a2, _ := Load("android-tvbox", "alpha")
	b, _ := Load("android-tvbox", "beta")
	if a1.Props["ro.serialno"] != a2.Props["ro.serialno"] {
		t.Fatal("same seed must give the same identifiers (a restart must not change the device)")
	}
	if a1.Props["ro.serialno"] == b.Props["ro.serialno"] || a1.Props["net.hostname"] == b.Props["net.hostname"] {
		t.Fatal("different seeds must give different identifiers (anti-fingerprinting)")
	}
	if len(a1.Props["ro.serialno"]) != 16 {
		t.Fatalf("serial: %q", a1.Props["ro.serialno"])
	}
	if !strings.HasPrefix(a1.Commands["ifconfig"], "eth0") || !strings.Contains(a1.Commands["ifconfig"], "00:1a:11:") {
		t.Fatalf("MAC must use the profile OUI: %q", a1.Commands["ifconfig"])
	}
}

func TestADBBanner(t *testing.T) {
	p, _ := Load("android-tvbox", "x")
	want := "device::ro.product.name=p212;ro.product.model=MXQ-4K;ro.product.device=p212;features=shell_v2,cmd"
	if got := p.ADBBanner(); got != want {
		t.Fatalf("banner=%q", got)
	}
}

func TestUnknownBuiltin(t *testing.T) {
	_, err := Load("nope", "")
	if err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("want helpful error, got %v", err)
	}
}

func TestLoadFromFileAndStrictness(t *testing.T) {
	dir := t.TempDir()
	good, _ := os.ReadFile("builtin/router-busybox.json")
	path := filepath.Join(dir, "mine.json")
	if err := os.WriteFile(path, []byte(strings.Replace(string(good), `"name": "router-busybox"`, `"name": "mine"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path, "s")
	if err != nil || p.Name != "mine" {
		t.Fatalf("file profile: %v %v", p, err)
	}

	bad := strings.Replace(string(good), `"kind"`, `"knd_typo": 1, "kind"`, 1)
	if _, err := Parse([]byte(bad), ""); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}

func TestValidationErrors(t *testing.T) {
	base, _ := os.ReadFile("builtin/router-busybox.json")
	cases := map[string]struct{ from, to string }{
		"bad kind":       {`"kind": "router"`, `"kind": "toaster"`},
		"bad hostname":   {`"hostname": "Router"`, `"hostname": "bad host!"`},
		"bad oui":        {`"oui": "00:e0:4c"`, `"oui": "zz"`},
		"relative file":  {`"/etc/hosts"`, `"etc/hosts"`},
		"bad not_found":  {`"not_found": "-sh: %s: not found"`, `"not_found": "nope"`},
		"bin with slash": {`"ash",`, `"/bin/ash",`},
	}
	for name, c := range cases {
		if !strings.Contains(string(base), c.from) {
			t.Fatalf("%s: fixture text %q not found", name, c.from)
		}
		bad := strings.Replace(string(base), c.from, c.to, 1)
		if _, err := Parse([]byte(bad), ""); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestOversizedProfileRejected(t *testing.T) {
	big := make([]byte, maxProfileBytes+1)
	if _, err := Parse(big, ""); err == nil {
		t.Fatal("oversized profile must be rejected")
	}
}

func TestHasBinAndApplet(t *testing.T) {
	p, _ := Load("android-tvbox", "x")
	if !p.HasBin("getprop") || p.HasBin("wget") {
		t.Fatal("android: getprop exists, wget is only a busybox applet")
	}
	if !p.HasApplet("wget") || p.HasApplet("nosuchthing") {
		t.Fatal("applet lookup")
	}
}

func TestPersistentSeedSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a, err := PersistentSeed(dir)
	if err != nil || len(a) != 32 {
		t.Fatalf("first seed: %q %v", a, err)
	}
	b, err := PersistentSeed(dir)
	if err != nil || a != b {
		t.Fatalf("seed must be stable across restarts: %q vs %q (%v)", a, b, err)
	}
	st, err := os.Stat(filepath.Join(dir, "profile.seed"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("seed file mode: %v %v", st, err)
	}
	other, _ := PersistentSeed(t.TempDir())
	if other == a {
		t.Fatal("seeds must be random per deployment")
	}
}

func TestPersistentSeedUnwritableDirStillReturnsSeed(t *testing.T) {
	seed, err := PersistentSeed("/proc/definitely/not/writable")
	if err == nil || seed == "" {
		t.Fatalf("want in-memory seed plus error, got %q %v", seed, err)
	}
}
