package profile

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

//go:embed builtin/*.json
var builtinFS embed.FS

const (
	KindAndroid = "android"
	KindRouter  = "router"
)

const (
	maxProfileBytes = 1 << 20
	maxFileBytes    = 64 << 10
	maxFiles        = 300
	maxProps        = 1500
	maxList         = 2000
)

type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind"`
	Hostname    string `json:"hostname"`
	OUI         string `json:"oui,omitempty"`

	Shell   Shell   `json:"shell"`
	ADB     ADB     `json:"adb"`
	Telnet  Telnet  `json:"telnet"`
	Kernel  Kernel  `json:"kernel"`
	Busybox Busybox `json:"busybox"`

	Props     map[string]string `json:"props,omitempty"`
	Packages  []string          `json:"packages,omitempty"`
	Proc      map[string]string `json:"proc,omitempty"`
	Files     map[string]string `json:"files,omitempty"`
	Dirs      []string          `json:"dirs,omitempty"`
	Bins      []string          `json:"bins,omitempty"`
	Processes []Process         `json:"processes,omitempty"`
	Commands  map[string]string `json:"commands,omitempty"`
	ExecRules []ExecRule        `json:"exec_rules,omitempty"`

	UptimeBaseSec int `json:"uptime_base_sec,omitempty"`
}

type ExecRule struct {
	Path     string `json:"path,omitempty"`
	FileType string `json:"file_type,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	Exit     int    `json:"exit,omitempty"`

	re *regexp.Regexp
}

func (r *ExecRule) Matches(p, fileType, sha string) bool {
	if r.re != nil && !r.re.MatchString(p) {
		return false
	}
	if r.FileType != "" && !strings.EqualFold(r.FileType, fileType) {
		return false
	}
	if r.SHA256 != "" && !strings.EqualFold(r.SHA256, sha) {
		return false
	}
	return true
}

func (p *Profile) NeedsHash() bool {
	for i := range p.ExecRules {
		if p.ExecRules[i].SHA256 != "" {
			return true
		}
	}
	return false
}

type Shell struct {
	User     string `json:"user"`
	UID      int    `json:"uid"`
	Home     string `json:"home"`
	Path     string `json:"path"`
	Prompt   string `json:"prompt"`
	NotFound string `json:"not_found"`
}

type ADB struct {
	Features string `json:"features"`
}

type Telnet struct {
	Pre              string `json:"pre,omitempty"`
	LoginPrompt      string `json:"login_prompt"`
	PasswordPrompt   string `json:"password_prompt"`
	FailureMessage   string `json:"failure_message"`
	FailuresBeforeOK int    `json:"failures_before_accept"`
	Welcome          string `json:"welcome,omitempty"`
	Prompt           string `json:"prompt,omitempty"`
}

type Kernel struct {
	Sysname string `json:"sysname"`
	Release string `json:"release"`
	Version string `json:"version"`
	Machine string `json:"machine"`
	OS      string `json:"os"`
}

type Busybox struct {
	Present bool     `json:"present"`
	Version string   `json:"version,omitempty"`
	Banner  string   `json:"banner,omitempty"`
	Applets []string `json:"applets,omitempty"`
}

type Process struct {
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	User  string `json:"user"`
	VSize int    `json:"vsize"`
	RSS   int    `json:"rss"`
	Name  string `json:"name"`
}

var (
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9{}_.-]{1,63}$`)
	ouiRe      = regexp.MustCompile(`^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){2}$`)
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

func Builtins() []string {
	entries, _ := builtinFS.ReadDir("builtin")
	var names []string
	for _, e := range entries {
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	return names
}

func Load(spec, seed string) (*Profile, error) {
	var raw []byte
	var err error
	if isPath(spec) {
		raw, err = readLimited(spec)
	} else {
		raw, err = builtinFS.ReadFile("builtin/" + spec + ".json")
		if err != nil {
			return nil, fmt.Errorf("profile %q: unknown built-in (available: %s)", spec, strings.Join(Builtins(), ", "))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", spec, err)
	}
	return Parse(raw, seed)
}

func isPath(spec string) bool {
	return strings.ContainsAny(spec, `/\`) || strings.HasSuffix(spec, ".json")
}

func readLimited(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxProfileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxProfileBytes {
		return nil, fmt.Errorf("file larger than %d bytes", maxProfileBytes)
	}
	return b, nil
}

func Parse(raw []byte, seed string) (*Profile, error) {
	if len(raw) > maxProfileBytes {
		return nil, errors.New("profile too large")
	}

	var pre Profile
	if err := strictDecode(raw, &pre); err != nil {
		return nil, err
	}
	if !hostnameRe.MatchString(pre.Hostname) {
		return nil, fmt.Errorf("profile: invalid hostname %q", pre.Hostname)
	}
	if pre.OUI != "" && !ouiRe.MatchString(pre.OUI) {
		return nil, fmt.Errorf("profile: invalid oui %q (want aa:bb:cc)", pre.OUI)
	}

	ids := deriveIDs(seed, pre.OUI)
	expanded := expand(raw, ids)

	var mid Profile
	if err := strictDecode(expanded, &mid); err != nil {
		return nil, err
	}
	expanded = bytes.ReplaceAll(expanded, []byte("{{hostname}}"), []byte(mid.Hostname))

	var p Profile
	if err := strictDecode(expanded, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("profile: %w", err)
	}
	if dec.More() {
		return errors.New("profile: trailing data after JSON document")
	}
	return nil
}

type ids struct{ serial, androidID, mac, ip, suffix string }

func deriveIDs(seed, oui string) ids {
	h := sha256.Sum256([]byte("github.com/generalregulator/botbait/profile/v1|" + seed))
	if oui == "" {
		oui = "00:1a:2b"
	}
	mac := strings.ToLower(oui) + fmt.Sprintf(":%02x:%02x:%02x", h[16], h[17], h[18])
	return ids{
		serial:    hex.EncodeToString(h[0:8]),
		androidID: hex.EncodeToString(h[8:16]),
		mac:       mac,
		ip:        fmt.Sprintf("192.168.%d.%d", 1+int(h[19])%3, 20+int(h[20])%200),
		suffix:    hex.EncodeToString(h[21:23]),
	}
}

func expand(raw []byte, i ids) []byte {
	return []byte(strings.NewReplacer(
		"{{serial}}", i.serial,
		"{{android_id}}", i.androidID,
		"{{mac}}", i.mac,
		"{{ip}}", i.ip,
		"{{suffix}}", i.suffix,
	).Replace(string(raw)))
}

func (p *Profile) Validate() error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	if !nameRe.MatchString(p.Name) {
		bad("name %q must match %s", p.Name, nameRe)
	}
	if p.Kind != KindAndroid && p.Kind != KindRouter {
		bad("kind must be %q or %q", KindAndroid, KindRouter)
	}
	if p.Hostname == "" || strings.Contains(p.Hostname, "{{") {
		bad("hostname unresolved: %q", p.Hostname)
	}
	if p.Shell.User == "" || p.Shell.Prompt == "" || !strings.Contains(p.Shell.NotFound, "%s") {
		bad("shell.user, shell.prompt and shell.not_found (with %%s) are required")
	}
	if p.Shell.UID < 0 || p.Shell.UID > 65535 {
		bad("shell.uid out of range")
	}
	if p.Telnet.LoginPrompt == "" || p.Telnet.PasswordPrompt == "" {
		bad("telnet.login_prompt and telnet.password_prompt are required")
	}
	if p.Telnet.FailuresBeforeOK < 0 || p.Telnet.FailuresBeforeOK > 5 {
		bad("telnet.failures_before_accept must be 0..5")
	}
	if p.Kernel.Sysname == "" || p.Kernel.Release == "" || p.Kernel.Machine == "" {
		bad("kernel.sysname/release/machine are required")
	}
	if len(p.Files) > maxFiles {
		bad("too many files (%d > %d)", len(p.Files), maxFiles)
	}
	if len(p.Props) > maxProps || len(p.Packages) > maxList || len(p.Bins) > maxList || len(p.Processes) > maxList {
		bad("list too long")
	}
	for k, v := range p.Files {
		if !validPath(k) {
			bad("files: %q is not a clean absolute path", k)
		}
		if len(v) > maxFileBytes {
			bad("files: %q larger than %d bytes", k, maxFileBytes)
		}
	}
	for k, v := range p.Proc {
		if k == "" || strings.HasPrefix(k, "/") || path.Clean(k) != k || strings.Contains(k, "..") {
			bad("proc: bad key %q", k)
		}
		if len(v) > maxFileBytes {
			bad("proc: %q larger than %d bytes", k, maxFileBytes)
		}
	}
	if len(p.ExecRules) > 50 {
		bad("too many exec_rules (%d > 50)", len(p.ExecRules))
	}
	for i := range p.ExecRules {
		r := &p.ExecRules[i]
		if r.Path == "" && r.FileType == "" && r.SHA256 == "" {
			bad("exec_rules[%d]: needs at least one of path, file_type, sha256", i)
		}
		if r.Path != "" {
			re, err := regexp.Compile(r.Path)
			if err != nil || len(r.Path) > 256 {
				bad("exec_rules[%d]: invalid path regexp", i)
			}
			r.re = re
		}
		if r.SHA256 != "" && !sha256Re.MatchString(r.SHA256) {
			bad("exec_rules[%d]: sha256 must be 64 hex characters", i)
		}
		if r.Exit < 0 || r.Exit > 255 {
			bad("exec_rules[%d]: exit must be 0..255", i)
		}
		if len(r.Stdout) > 4096 || len(r.Stderr) > 4096 {
			bad("exec_rules[%d]: stdout/stderr larger than 4096 bytes", i)
		}
	}
	for _, d := range p.Dirs {
		if !validPath(d) {
			bad("dirs: %q is not a clean absolute path", d)
		}
	}
	for _, b := range p.Bins {
		if b == "" || strings.ContainsAny(b, "/ \t\n") {
			bad("bins: %q must be a bare command name", b)
		}
	}
	for _, b := range p.Busybox.Applets {
		if b == "" || strings.ContainsAny(b, "/ \t\n") {
			bad("busybox.applets: %q must be a bare applet name", b)
		}
	}
	if p.Busybox.Present && p.Busybox.Banner == "" {
		bad("busybox.banner is required when busybox.present is true")
	}
	if len(errs) > 0 {
		return fmt.Errorf("profile %q invalid:\n  - %s", p.Name, strings.Join(errs, "\n  - "))
	}
	return nil
}

func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.Contains(p, "\x00") && p != "/"
}

func (p *Profile) ADBBanner() string {
	get := func(k string) string { return p.Props[k] }
	var b strings.Builder
	b.WriteString("device::")
	fmt.Fprintf(&b, "ro.product.name=%s;ro.product.model=%s;ro.product.device=%s",
		get("ro.product.name"), get("ro.product.model"), get("ro.product.device"))
	if p.ADB.Features != "" {
		b.WriteString(";features=" + p.ADB.Features)
	}
	return b.String()
}

func (p *Profile) HasBin(name string) bool {
	for _, b := range p.Bins {
		if b == name {
			return true
		}
	}
	return false
}

func (p *Profile) HasApplet(name string) bool {
	if !p.Busybox.Present {
		return false
	}
	for _, a := range p.Busybox.Applets {
		if a == name {
			return true
		}
	}
	return false
}

func PersistentSeed(dir string) (string, error) {
	file := path.Join(dir, "profile.seed")
	if b, err := os.ReadFile(file); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	seed := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return seed, err
	}
	if err := os.WriteFile(file, []byte(seed+"\n"), 0o600); err != nil {
		return seed, err
	}
	return seed, nil
}
