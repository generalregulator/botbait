package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/generalregulator/botbait/internal/digest"
	"github.com/generalregulator/botbait/internal/webcam"
)

const (
	MaxDownloadTimeout = 5 * time.Second
	MaxDownloadBytes   = 15 * 1024 * 1024

	MaxPushBytes          = 15 * 1024 * 1024
	MaxPushSessionTimeout = 120 * time.Second
)

type Config struct {
	Ports           []int
	TelnetPorts     []int
	WebPorts        map[int]string
	PortLabels      map[int]int
	MaxConns        int
	MaxConnsPerIP   int
	QueueSize       int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	SessionTimeout  time.Duration
	MaxReadBytes    int
	ShutdownTimeout time.Duration

	RateLimit   float64
	RateBurst   int
	RatePrefix4 int
	RatePrefix6 int

	PipelineWorkers int
	EventQueue      int
	LogDir          string
	StorePayloadMax int

	DownloadEnabled      bool
	PayloadDir           string
	DownloadTimeout      time.Duration
	MaxDownloadBytes     int64
	MaxDownloadsPerEvent int
	DownloadWorkers      int
	MaxStorageBytes      int64

	Profile            string
	TelnetProfile      string
	ProfileSeed        string
	CapturePush        bool
	MaxPushBytes       int64
	PushSessionTimeout time.Duration

	EnrichEnabled bool
	EnrichTimeout time.Duration

	TelegramToken   string
	TelegramChatID  string
	TelegramPerMin  int
	TelegramBurst   int
	AlertCooldown   time.Duration
	AlertCampaign   time.Duration
	AbuseKey        string
	AbuseReport     bool
	AbuseBrute      bool
	AbuseWindow     time.Duration
	AbuseState      string
	AlertState      string
	AlertPayloadMax int
	AlertOnBrute    bool

	DigestEnabled   bool
	DigestDay       string
	DigestAt        string
	DigestTop       int
	DigestEnrichMax int

	MetricsAddr string
	LogLevel    string
}

func Load() (*Config, error) {
	var errs []error
	e := &envReader{}

	c := &Config{
		MaxConns:        e.int("HP_MAX_CONNS", 256),
		MaxConnsPerIP:   e.int("HP_MAX_CONNS_PER_IP", 8),
		ReadTimeout:     e.dur("HP_READ_TIMEOUT", 5*time.Second),
		WriteTimeout:    e.dur("HP_WRITE_TIMEOUT", 5*time.Second),
		SessionTimeout:  e.dur("HP_SESSION_TIMEOUT", 20*time.Second),
		MaxReadBytes:    e.int("HP_MAX_READ_BYTES", 64*1024),
		ShutdownTimeout: e.dur("HP_SHUTDOWN_TIMEOUT", 20*time.Second),

		RateLimit:   e.float("HP_RATE_PER_SEC", 1),
		RateBurst:   e.int("HP_RATE_BURST", 10),
		RatePrefix4: e.int("HP_RATE_PREFIX_V4", 24),
		RatePrefix6: e.int("HP_RATE_PREFIX_V6", 64),

		PipelineWorkers: e.int("HP_PIPELINE_WORKERS", 8),
		EventQueue:      e.int("HP_EVENT_QUEUE", 1024),
		LogDir:          e.str("HP_LOG_DIR", "./data"),
		StorePayloadMax: e.int("HP_STORE_PAYLOAD_MAX", 8192),

		DownloadEnabled:      e.bool("HP_DOWNLOAD_ENABLED", true),
		PayloadDir:           e.str("HP_PAYLOAD_DIR", "./captured_payloads"),
		DownloadTimeout:      e.dur("HP_DOWNLOAD_TIMEOUT", MaxDownloadTimeout),
		MaxDownloadBytes:     int64(e.int("HP_MAX_DOWNLOAD_BYTES", MaxDownloadBytes)),
		MaxDownloadsPerEvent: e.int("HP_MAX_DOWNLOADS_PER_EVENT", 3),
		DownloadWorkers:      e.int("HP_DOWNLOAD_WORKERS", 4),
		MaxStorageBytes:      int64(e.int("HP_MAX_STORAGE_MB", 512)) * 1024 * 1024,

		Profile:            e.str("HP_PROFILE", "android-tvbox"),
		TelnetProfile:      e.str("HP_TELNET_PROFILE", ""),
		ProfileSeed:        e.str("HP_PROFILE_SEED", ""),
		CapturePush:        e.bool("HP_CAPTURE_PUSH", true),
		MaxPushBytes:       int64(e.int("HP_MAX_PUSH_BYTES", MaxPushBytes)),
		PushSessionTimeout: e.dur("HP_PUSH_SESSION_TIMEOUT", 60*time.Second),

		EnrichEnabled: e.bool("HP_ENRICH_ENABLED", true),
		EnrichTimeout: e.dur("HP_ENRICH_TIMEOUT", 3*time.Second),

		TelegramToken:   e.str("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:  e.str("TELEGRAM_CHAT_ID", ""),
		TelegramPerMin:  e.int("HP_TG_PER_MIN", 20),
		TelegramBurst:   e.int("HP_TG_BURST", 5),
		AlertCooldown:   e.dur("HP_ALERT_COOLDOWN", 6*time.Hour),
		AlertCampaign:   e.dur("HP_ALERT_CAMPAIGN_COOLDOWN", 6*time.Hour),
		AbuseKey:        e.str("ABUSEIPDB_API_KEY", ""),
		AbuseReport:     e.bool("HP_ABUSE_REPORT", true),
		AbuseBrute:      e.bool("HP_ABUSE_REPORT_BRUTE", true),
		AbuseWindow:     e.dur("HP_ABUSE_WINDOW", 24*time.Hour),
		AbuseState:      e.str("HP_ABUSE_STATE", ""),
		AlertState:      e.str("HP_ALERT_STATE", ""),
		AlertPayloadMax: e.int("HP_ALERT_PAYLOAD_MAX", 1200),
		AlertOnBrute:    e.bool("HP_ALERT_ON_BRUTE", false),

		DigestEnabled:   e.bool("HP_DIGEST_ENABLED", true),
		DigestDay:       e.str("HP_DIGEST_DAY", "mon"),
		DigestAt:        e.str("HP_DIGEST_AT", "09:00"),
		DigestTop:       e.int("HP_DIGEST_TOP", 10),
		DigestEnrichMax: e.int("HP_DIGEST_ENRICH_MAX", 200),

		MetricsAddr: e.str("HP_METRICS_ADDR", "127.0.0.1:9100"),
		LogLevel:    e.str("HP_LOG_LEVEL", "info"),
	}
	c.QueueSize = e.int("HP_QUEUE_SIZE", c.MaxConns)

	ports, err := parsePorts(e.str("HP_PORTS", "5555,7547,2323,8088,8081,8080"))
	if err != nil {
		errs = append(errs, err)
	}
	c.Ports = ports

	tports, err := parsePorts(e.str("HP_TELNET_PORTS", "23,2323"))
	if err != nil {
		errs = append(errs, err)
	}
	c.TelnetPorts = tports

	wports, err := parseWebPorts(e.str("HP_WEB_PORTS", "8088=hikvision,8081=tvt,8080=dahua"))
	if err != nil {
		errs = append(errs, err)
	}
	c.WebPorts = wports

	labels, err := parsePortLabels(e.str("HP_PORT_LABELS", "2323:23,8088:80,8081:81"))
	if err != nil {
		errs = append(errs, err)
	}
	c.PortLabels = labels

	errs = append(errs, e.errs...)
	if err := c.Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func (c *Config) Validate() error {
	var errs []error
	chk := func(ok bool, format string, a ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, a...))
		}
	}
	chk(len(c.Ports) > 0, "HP_PORTS must contain at least one port")
	chk(c.MaxConns > 0 && c.MaxConns <= 10000, "HP_MAX_CONNS must be in 1..10000")
	chk(c.MaxConnsPerIP > 0, "HP_MAX_CONNS_PER_IP must be > 0")
	chk(c.QueueSize >= 0, "HP_QUEUE_SIZE must be >= 0")
	chk(c.ReadTimeout > 0 && c.WriteTimeout > 0 && c.SessionTimeout > 0, "timeouts must be > 0")
	chk(c.MaxReadBytes >= 1024 && c.MaxReadBytes <= 1<<20, "HP_MAX_READ_BYTES must be in 1KiB..1MiB")
	chk(c.RateLimit > 0 && c.RateBurst > 0, "HP_RATE_PER_SEC and HP_RATE_BURST must be > 0")
	chk(c.RatePrefix4 >= 8 && c.RatePrefix4 <= 32, "HP_RATE_PREFIX_V4 must be in 8..32")
	chk(c.RatePrefix6 >= 16 && c.RatePrefix6 <= 128, "HP_RATE_PREFIX_V6 must be in 16..128")
	chk(c.PipelineWorkers > 0 && c.EventQueue > 0, "pipeline workers/queue must be > 0")
	chk(c.DownloadTimeout > 0 && c.DownloadTimeout <= MaxDownloadTimeout,
		"HP_DOWNLOAD_TIMEOUT must be in (0, %s]", MaxDownloadTimeout)
	chk(c.MaxDownloadBytes > 0 && c.MaxDownloadBytes <= MaxDownloadBytes,
		"HP_MAX_DOWNLOAD_BYTES must be in (0, %d]", MaxDownloadBytes)
	chk(c.MaxDownloadsPerEvent >= 0 && c.DownloadWorkers > 0, "download limits invalid")
	chk(c.MaxStorageBytes > 0, "HP_MAX_STORAGE_MB must be > 0")
	chk(c.MaxPushBytes > 0 && c.MaxPushBytes <= MaxPushBytes,
		"HP_MAX_PUSH_BYTES must be in (0, %d]", MaxPushBytes)
	chk(c.PushSessionTimeout >= c.SessionTimeout && c.PushSessionTimeout <= MaxPushSessionTimeout,
		"HP_PUSH_SESSION_TIMEOUT must be in [HP_SESSION_TIMEOUT, %s]", MaxPushSessionTimeout)
	chk(c.Profile != "", "HP_PROFILE must not be empty")
	for p := range c.WebPorts {
		chk(!c.IsTelnet(p), "HP_WEB_PORTS port %d is also a Telnet port", p)
	}
	chk((c.TelegramToken == "") == (c.TelegramChatID == ""),
		"TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set together")
	chk(c.TelegramPerMin > 0 && c.TelegramBurst > 0, "Telegram rate limits must be > 0")
	chk(c.AlertCooldown >= 0 && c.AlertCampaign >= 0, "HP_ALERT_COOLDOWN and HP_ALERT_CAMPAIGN_COOLDOWN must not be negative")
	chk(c.AbuseKey == "" || abuseKeyRe.MatchString(c.AbuseKey), "ABUSEIPDB_API_KEY must be 20..128 letters and digits (copy it from the API page of your AbuseIPDB account)")
	chk(c.AbuseWindow >= time.Hour, "HP_ABUSE_WINDOW must be at least 1h (the same address is reported once per window)")
	chk(c.AlertPayloadMax >= 100 && c.AlertPayloadMax <= 3000, "HP_ALERT_PAYLOAD_MAX must be in 100..3000")
	_, derr := time.Parse("15:04", c.DigestAt)
	chk(derr == nil, "HP_DIGEST_AT must be HH:MM (UTC), e.g. 09:00")
	_, dayOK := digest.ParseWeekday(c.DigestDay)
	chk(dayOK, "HP_DIGEST_DAY must be a weekday, e.g. mon or sunday")
	chk(c.DigestTop >= 1 && c.DigestTop <= 10, "HP_DIGEST_TOP must be in 1..10")
	chk(c.DigestEnrichMax >= 0 && c.DigestEnrichMax <= 500, "HP_DIGEST_ENRICH_MAX must be in 0..500")
	return errors.Join(errs...)
}

func (c *Config) AlertStatePath() string {
	switch c.AlertState {
	case "off":
		return ""
	case "":
		return filepath.Join(c.LogDir, "alert-state.json")
	}
	return c.AlertState
}

var abuseKeyRe = regexp.MustCompile(`^[A-Za-z0-9]{20,128}$`)

func (c *Config) AbuseEnabled() bool { return c.AbuseReport && c.AbuseKey != "" }

func (c *Config) AbuseStatePath() string {
	switch c.AbuseState {
	case "off":
		return ""
	case "":
		return filepath.Join(c.LogDir, "abuseipdb-state.json")
	}
	return c.AbuseState
}

func (c *Config) TelegramEnabled() bool { return c.TelegramToken != "" && c.TelegramChatID != "" }

func (c *Config) IsTelnet(p int) bool {
	for _, t := range c.TelnetPorts {
		if t == p {
			return true
		}
	}
	return false
}

func (c *Config) WebVendor(p int) (webcam.Vendor, bool) {
	v, ok := c.WebPorts[p]
	return webcam.Vendor(v), ok
}

func (c *Config) PublicPort(p int) int {
	if l, ok := c.PortLabels[p]; ok {
		return l
	}
	return p
}

func parseWebPorts(s string) (map[int]string, error) {
	out := map[int]string{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		ps, vs, ok := strings.Cut(f, "=")
		port, err := strconv.Atoi(strings.TrimSpace(ps))
		if !ok || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("HP_WEB_PORTS: %q must look like 8088=hikvision", f)
		}
		v, known := webcam.ParseVendor(vs)
		if !known {
			return nil, fmt.Errorf("HP_WEB_PORTS: unknown vendor %q (use hikvision, dahua or tvt)", strings.TrimSpace(vs))
		}
		out[port] = string(v)
	}
	return out, nil
}

func parsePortLabels(s string) (map[int]int, error) {
	out := map[int]int{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, b, ok := strings.Cut(f, ":")
		from, e1 := strconv.Atoi(strings.TrimSpace(a))
		to, e2 := strconv.Atoi(strings.TrimSpace(b))
		if !ok || e1 != nil || e2 != nil || from < 1 || from > 65535 || to < 1 || to > 65535 {
			return nil, fmt.Errorf("HP_PORT_LABELS: %q must look like 8088:80", f)
		}
		out[from] = to
	}
	return out, nil
}

func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		p, err := strconv.Atoi(f)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("HP_PORTS: invalid port %q", f)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "export "))
		v = parseDotEnvValue(v)
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
	return sc.Err()
}

func parseDotEnvValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : 1+end]
		}
	}
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			v = v[:i]
			break
		}
	}
	return strings.TrimSpace(v)
}

type envReader struct{ errs []error }

func (r *envReader) str(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func (r *envReader) int(k string, def int) int {
	v := r.str(k, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s: invalid integer %q", k, v))
		return def
	}
	return n
}

func (r *envReader) float(k string, def float64) float64 {
	v := r.str(k, "")
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s: invalid number %q", k, v))
		return def
	}
	return n
}

func (r *envReader) bool(k string, def bool) bool {
	v := r.str(k, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s: invalid boolean %q", k, v))
		return def
	}
	return b
}

func (r *envReader) dur(k string, def time.Duration) time.Duration {
	v := r.str(k, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		r.errs = append(r.errs, fmt.Errorf("%s: invalid duration %q", k, v))
		return def
	}
	return d
}
