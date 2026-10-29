package abuseipdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
)

const (
	DefaultBase    = "https://api.abuseipdb.com"
	maxComment     = 900
	maxRemembered  = 20000
	maxPauseWait   = 15 * time.Minute
	defaultWindow  = 24 * time.Hour
	defaultQueue   = 256
	maxAttempts    = 4
	requestTimeout = 15 * time.Second
)

const (
	CatHacking      = 15
	CatBruteForce   = 18
	CatExploited    = 20
	CatWebAppAttack = 21
	CatIoTTargeted  = 23
)

type Options struct {
	Key       string
	Base      string
	StatePath string
	Window    time.Duration
	Queue     int
	Client    *http.Client
	Metrics   *metrics.Metrics
	Log       *slog.Logger
	Now       func() time.Time
	Sleep     func(ctx context.Context, d time.Duration) bool

	AllowNonPublic bool
}

type job struct {
	ip         string
	categories []int
	comment    string
	at         time.Time
}

type Reporter struct {
	key, base string
	statePath string
	window    time.Duration
	client    *http.Client
	m         *metrics.Metrics
	log       *slog.Logger
	now       func() time.Time
	sleep     func(ctx context.Context, d time.Duration) bool
	anyIP     bool

	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan job
	done     chan struct{}
	disabled atomic.Bool

	mu          sync.Mutex
	reported    map[string]time.Time
	pending     map[string]bool
	pausedUntil time.Time
	closed      bool
}

func New(o Options) *Reporter {
	if o.Base == "" {
		o.Base = DefaultBase
	}
	if o.Window <= 0 {
		o.Window = defaultWindow
	}
	if o.Queue <= 0 {
		o.Queue = defaultQueue
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: requestTimeout}
	}
	if o.Metrics == nil {
		o.Metrics = &metrics.Metrics{}
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	rctx, rcancel := context.WithCancel(context.Background())
	r := &Reporter{
		ctx: rctx, cancel: rcancel,
		key: o.Key, base: strings.TrimRight(o.Base, "/"), statePath: o.StatePath, window: o.Window,
		client: o.Client, m: o.Metrics, log: o.Log, now: o.Now, sleep: o.Sleep, anyIP: o.AllowNonPublic,
		queue: make(chan job, o.Queue), done: make(chan struct{}),
		reported: map[string]time.Time{}, pending: map[string]bool{},
	}
	r.load()
	return r
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *Reporter) Start() {
	go func() {
		defer close(r.done)
		for j := range r.queue {
			r.send(r.ctx, j)
		}
	}()
}

func (r *Reporter) Stop(timeout time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.mu.Unlock()
	defer r.cancel()
	select {
	case <-r.done:
		return
	case <-time.After(timeout):
	}
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(time.Second):
	}
}

func (r *Reporter) Submit(ev *model.Event) bool {
	if r == nil || r.disabled.Load() {
		return false
	}
	addr, err := netip.ParseAddr(ev.SrcIP)
	if err != nil || (!r.anyIP && !publicIP(addr)) {
		return false
	}
	ip := addr.Unmap().String()
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.pending[ip] {
		r.m.AbuseSkipped.Add(1)
		return false
	}
	if at, ok := r.reported[ip]; ok && now.Sub(at) < r.window {
		r.m.AbuseSkipped.Add(1)
		return false
	}
	j := job{ip: ip, categories: Categories(ev), comment: Comment(ev), at: ev.Timestamp}
	select {
	case r.queue <- j:
		r.pending[ip] = true
		return true
	default:
		r.m.AbuseSkipped.Add(1)
		return false
	}
}

func (r *Reporter) finish(ip string, remember bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, ip)
	if remember {
		r.reported[ip] = r.now()
		r.pruneLocked()
		r.saveLocked()
	}
}

func (r *Reporter) send(ctx context.Context, j job) {
	if r.disabled.Load() {
		r.finish(j.ip, false)
		return
	}
	r.mu.Lock()
	paused := r.now().Before(r.pausedUntil)
	r.mu.Unlock()
	if paused {
		r.m.AbuseSkipped.Add(1)
		r.finish(j.ip, false)
		return
	}
	backoff := []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, retryAfter, err := r.post(ctx, j)
		switch {
		case err == nil && status == http.StatusOK:
			r.m.AbuseReported.Add(1)
			r.finish(j.ip, true)
			return
		case err == nil && status == http.StatusUnprocessableEntity:
			r.log.Debug("abuseipdb: report not accepted (already reported or invalid)", "ip", j.ip)
			r.finish(j.ip, true)
			return
		case err == nil && (status == http.StatusUnauthorized || status == http.StatusForbidden):
			r.disabled.Store(true)
			r.m.AbuseErrors.Add(1)
			r.log.Error("abuseipdb: the API key was rejected; automatic reporting is switched off until restart", "status", status)
			r.finish(j.ip, false)
			return
		case err == nil && status == http.StatusTooManyRequests:
			if retryAfter <= 0 {
				retryAfter = time.Minute
			}
			r.m.AbuseErrors.Add(1)
			if retryAfter > maxPauseWait {
				r.mu.Lock()
				r.pausedUntil = r.now().Add(retryAfter)
				r.mu.Unlock()
				r.log.Warn("abuseipdb: daily limit reached, pausing reports", "retry_after", retryAfter.Round(time.Second))
				r.finish(j.ip, false)
				return
			}
			if !r.sleep(ctx, retryAfter) {
				r.finish(j.ip, false)
				return
			}
		default:
			r.m.AbuseErrors.Add(1)
			if err != nil {
				r.log.Debug("abuseipdb: request failed", "err", redact(err, r.key))
			} else {
				r.log.Debug("abuseipdb: unexpected status", "status", status)
			}
			if attempt >= len(backoff) || !r.sleep(ctx, backoff[attempt]) {
				r.finish(j.ip, false)
				return
			}
		}
	}
	r.finish(j.ip, false)
}

func (r *Reporter) post(ctx context.Context, j job) (int, time.Duration, error) {
	cats := make([]string, len(j.categories))
	for i, c := range j.categories {
		cats[i] = strconv.Itoa(c)
	}
	form := url.Values{}
	form.Set("ip", j.ip)
	form.Set("categories", strings.Join(cats, ","))
	form.Set("comment", j.comment)
	if !j.at.IsZero() {
		form.Set("timestamp", j.at.UTC().Format(time.RFC3339))
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, r.base+"/api/v2/report", strings.NewReader(form.Encode()))
	if err != nil {
		return 0, 0, errors.New("abuseipdb: cannot build request")
	}
	req.Header.Set("Key", r.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	var ra time.Duration
	if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
		ra = time.Duration(s) * time.Second
	}
	return resp.StatusCode, ra, nil
}

func (r *Reporter) pruneLocked() {
	if len(r.reported) < maxRemembered {
		return
	}
	cutoff := r.now().Add(-r.window)
	for ip, at := range r.reported {
		if at.Before(cutoff) {
			delete(r.reported, ip)
		}
	}
	if len(r.reported) < maxRemembered {
		return
	}
	type kv struct {
		ip string
		at time.Time
	}
	all := make([]kv, 0, len(r.reported))
	for ip, at := range r.reported {
		all = append(all, kv{ip, at})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for _, e := range all[:len(all)-maxRemembered*4/5] {
		delete(r.reported, e.ip)
	}
}

func (r *Reporter) load() {
	if r.statePath == "" {
		return
	}
	raw, err := os.ReadFile(r.statePath)
	if err != nil {
		return
	}
	var disk map[string]int64
	if json.Unmarshal(raw, &disk) != nil {
		return
	}
	now := r.now()
	for ip, ts := range disk {
		at := time.Unix(ts, 0)
		if now.Sub(at) < r.window && len(r.reported) < maxRemembered {
			r.reported[ip] = at
		}
	}
}

func (r *Reporter) saveLocked() {
	if r.statePath == "" {
		return
	}
	disk := make(map[string]int64, len(r.reported))
	for ip, at := range r.reported {
		disk[ip] = at.Unix()
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return
	}
	tmp := r.statePath + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		if os.Rename(tmp, r.statePath) != nil {
			_ = os.Remove(tmp)
		}
	}
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func Categories(ev *model.Event) []int {
	set := map[int]bool{}
	web := ev.Protocol == "HTTP"
	iot := ev.Persona != "" || ev.Protocol == "ADB" || ev.Protocol == "TELNET" || strings.Contains(strings.ToLower(ev.HTTPPath), "/ud/act")
	if iot {
		set[CatIoTTargeted] = true
	}
	if ev.HasTechnique("T1190") {
		set[CatHacking] = true
		set[CatExploited] = true
		if web {
			set[CatWebAppAttack] = true
		}
	}
	if ev.HasTechnique("T1059.004") || ev.HasTechnique("T1105") || ev.HasTechnique("T1496") {
		set[CatHacking] = true
		set[CatExploited] = true
	}
	if ev.HasTechnique("T1110.001") {
		set[CatBruteForce] = true
	}
	if len(set) == 0 {
		set[CatHacking] = true
	}
	out := make([]int, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Ints(out)
	return out
}

func Comment(ev *model.Event) string {
	var parts []string
	what := strings.TrimSpace(ev.Signature)
	if what == "" {
		what = strings.TrimSpace(ev.Action)
	}
	head := "BotBait IoT honeypot"
	switch {
	case ev.Persona != "":
		head += " (" + ev.Persona + " camera/DVR web)"
	case ev.Protocol == "ADB":
		head += " (Android Debug Bridge)"
	case ev.Protocol == "TELNET":
		head += " (router Telnet)"
	}
	line := head
	if what != "" {
		line += ": " + clean(what, 120)
	}
	line += fmt.Sprintf(" on %d/%s", ev.DstPort, clean(ev.Protocol, 12))
	parts = append(parts, line+".")
	if ids := ev.TechniqueIDs(); len(ids) > 0 {
		parts = append(parts, "ATT&CK: "+strings.Join(ids, ", ")+".")
	}
	if ev.HTTPMethod != "" && ev.HTTPPath != "" {
		parts = append(parts, "Request: "+clean(ev.HTTPMethod, 8)+" "+clean(defangText(ev.HTTPPath), 160)+".")
	}
	if n := len(ev.Credentials); n >= 2 {
		parts = append(parts, fmt.Sprintf("%d login attempts.", n))
	}
	var drops []string
	for _, u := range ev.IOCs.DownloadURLs {
		if d := Defang(u); d != "" {
			drops = append(drops, d)
		}
		if len(drops) == 2 {
			break
		}
	}
	for _, n := range ev.IOCs.NFS {
		if len(drops) < 3 {
			drops = append(drops, "nfs "+defangHost(n))
		}
	}
	if len(drops) > 0 {
		parts = append(parts, "Dropper: "+strings.Join(drops, " ")+".")
	}
	for _, d := range ev.Downloads {
		if d.Success && d.SHA256 != "" {
			parts = append(parts, "Sample SHA256: "+d.SHA256+".")
			break
		}
	}
	out := strings.Join(parts, " ")
	if len(out) > maxComment {
		out = out[:maxComment]
	}
	return out
}

var urlInText = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>` + "`" + `|;&]+`)

func defangText(s string) string {
	return urlInText.ReplaceAllStringFunc(s, func(m string) string {
		if d := Defang(m); d != "" {
			return d
		}
		return "[url]"
	})
}

func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= n {
			break
		}
	}
	return b.String()
}

func Defang(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "http" {
		scheme = "hxxp"
	} else if scheme == "https" {
		scheme = "hxxps"
	}
	host := strings.ReplaceAll(u.Host, ".", "[.]")
	return clean(scheme+"://"+host+u.EscapedPath(), 140)
}

func defangHost(s string) string {
	host, rest, _ := strings.Cut(s, ":")
	return clean(strings.ReplaceAll(host, ".", "[.]")+":"+rest, 100)
}

func redact(err error, key string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, "abuseipdb", ue.Err)
	}
	if key != "" && strings.Contains(err.Error(), key) {
		return errors.New("abuseipdb: request failed")
	}
	return err
}

func Validate(ctx context.Context, key, base string) error {
	if base == "" {
		base = DefaultBase
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	endpoint := strings.TrimRight(base, "/") + "/api/v2/check?ipAddress=" + url.QueryEscape("127.0.0.1") + "&maxAgeInDays=1"
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errors.New("AbuseIPDB did not answer in time")
		}
		return errors.New("cannot reach AbuseIPDB")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("AbuseIPDB rejected the API key")
	}
	return fmt.Errorf("AbuseIPDB answered HTTP %d", resp.StatusCode)
}
