package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Ports, []int{5555, 7547, 2323, 8088, 8081, 8080}) {
		t.Fatalf("default ports: %v", c.Ports)
	}
	if !c.IsTelnet(2323) || c.IsTelnet(5555) {
		t.Fatal("telnet port detection wrong")
	}
	if v, ok := c.WebVendor(8088); !ok || v != "hikvision" {
		t.Fatalf("web vendor for 8088: %q %v", v, ok)
	}
	if _, ok := c.WebVendor(5555); ok {
		t.Fatal("ADB port must not be a web persona")
	}
	if c.PublicPort(8088) != 80 || c.PublicPort(2323) != 23 || c.PublicPort(5555) != 5555 {
		t.Fatalf("public port labels: %v", c.PortLabels)
	}
	if c.DownloadTimeout != MaxDownloadTimeout || c.MaxDownloadBytes != MaxDownloadBytes {
		t.Fatalf("download ceilings: %v %v", c.DownloadTimeout, c.MaxDownloadBytes)
	}
	if c.TelegramEnabled() {
		t.Fatal("telegram must be off without credentials")
	}
	if !c.CapturePush || c.MaxPushBytes != MaxPushBytes || c.Profile != "android-tvbox" || c.TelnetProfile != "" {
		t.Fatalf("persona/push defaults: %+v", c)
	}
}

func TestSafetyCeilingsAreEnforced(t *testing.T) {
	cases := map[string]string{
		"HP_DOWNLOAD_TIMEOUT":     "6s",
		"HP_MAX_DOWNLOAD_BYTES":   "15728641",
		"HP_PORTS":                "5555,70000",
		"HP_MAX_CONNS":            "0",
		"HP_MAX_PUSH_BYTES":       "15728641",
		"HP_PUSH_SESSION_TIMEOUT": "121s",
		"TELEGRAM_BOT_TOKEN":      "123:abc",
		"ABUSEIPDB_API_KEY":       "short key!",
		"HP_ABUSE_WINDOW":         "30m",
	}
	for k, v := range cases {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s must be rejected", k, v)
			}
		})
	}
}

func TestInvalidValuesAreReportedTogether(t *testing.T) {
	t.Setenv("HP_MAX_CONNS", "many")
	t.Setenv("HP_READ_TIMEOUT", "soon")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "HP_MAX_CONNS") || !strings.Contains(err.Error(), "HP_READ_TIMEOUT") {
		t.Fatalf("expected both errors, got %v", err)
	}
}

func TestExampleEnvFileLoads(t *testing.T) {
	path := filepath.Join("..", "..", ".env.example")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no .env.example:", err)
	}

	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if k, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && !strings.HasPrefix(k, "#") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	if err := LoadDotEnv(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("shipped .env.example does not validate: %v", err)
	}
	if c.MaxConns != 256 || c.DownloadTimeout.Seconds() != 5 || c.TelegramEnabled() {
		t.Fatalf("unexpected values: conns=%d dl=%v tg=%v", c.MaxConns, c.DownloadTimeout, c.TelegramEnabled())
	}
}

func TestDotEnvValueParsing(t *testing.T) {
	for in, want := range map[string]string{
		`256   # comment`:     "256",
		`"a # b"`:             "a # b",
		`'quoted' # trailing`: "quoted",
		`http://x/#frag`:      "http://x/#frag",
		`   spaced   `:        "spaced",
		``:                    "",
	} {
		if got := parseDotEnvValue(in); got != want {
			t.Errorf("parseDotEnvValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDotEnvDoesNotOverrideEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# comment\nHP_PORTS=9001, 9002\nHP_LOG_LEVEL=\"debug\"\n"), 0o600)
	t.Setenv("HP_LOG_LEVEL", "warn")
	os.Unsetenv("HP_PORTS")
	t.Cleanup(func() { os.Unsetenv("HP_PORTS") })
	if err := LoadDotEnv(p); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Ports, []int{9001, 9002}) || c.LogLevel != "warn" {
		t.Fatalf("ports=%v level=%s", c.Ports, c.LogLevel)
	}
	if err := LoadDotEnv(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal("missing .env must not be an error")
	}
}

func TestWebPortAndLabelSettingsAreValidated(t *testing.T) {
	cases := map[string]string{
		"HP_WEB_PORTS":   "8088=axis",
		"HP_PORT_LABELS": "8088-80",
	}
	for k, v := range cases {
		t.Setenv(k, v)
		if _, err := Load(); err == nil {
			t.Errorf("%s=%q must be rejected", k, v)
		}
		t.Setenv(k, "")
	}
	t.Setenv("HP_WEB_PORTS", "2323=dahua")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "Telnet") {
		t.Errorf("a Telnet port cannot be a web persona: %v", err)
	}
	t.Setenv("HP_WEB_PORTS", "9000=tvt, 9001 = dahua")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := c.WebVendor(9001); v != "dahua" {
		t.Errorf("spaces around entries: %v", c.WebPorts)
	}
}

func TestAbuseIPDBSettings(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.AbuseEnabled() || !c.AbuseReport || !c.AbuseBrute || c.AbuseWindow.Hours() != 24 {
		t.Fatalf("defaults: enabled=%v report=%v brute=%v window=%v", c.AbuseEnabled(), c.AbuseReport, c.AbuseBrute, c.AbuseWindow)
	}
	t.Setenv("ABUSEIPDB_API_KEY", strings.Repeat("a1", 40))
	c, err = Load()
	if err != nil || !c.AbuseEnabled() {
		t.Fatalf("a valid key must enable reporting: %v", err)
	}
	t.Setenv("HP_ABUSE_REPORT", "false")
	if c, _ = Load(); c.AbuseEnabled() {
		t.Fatal("HP_ABUSE_REPORT=false must pause reporting without removing the key")
	}
	if got := c.AbuseStatePath(); !strings.HasSuffix(got, "abuseipdb-state.json") {
		t.Fatalf("default state path %q", got)
	}
	t.Setenv("HP_ABUSE_STATE", "off")
	if c, _ = Load(); c.AbuseStatePath() != "" {
		t.Fatal("HP_ABUSE_STATE=off must disable the state file")
	}
}

func TestRedactionSettings(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !c.RedactEnabled || !c.RedactAutodetect || c.PublicIPURL != "https://api.ipify.org" || c.RedactExtra != "" {
		t.Fatalf("defaults: %+v", c)
	}
	t.Setenv("HP_PUBLIC_IP_URL", "http://plain.example/ip")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HP_PUBLIC_IP_URL") {
		t.Fatalf("plain http accepted: %v", err)
	}
	t.Setenv("HP_PUBLIC_IP_URL", "off")
	if _, err := Load(); err != nil {
		t.Fatalf("off rejected: %v", err)
	}
}
