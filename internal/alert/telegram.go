package alert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/ratelimit"
)

const defaultAPI = "https://api.telegram.org"

type Notifier struct {
	token      string
	chatID     string
	base       string
	client     *http.Client
	lim        *ratelimit.Bucket
	cooldown   time.Duration
	campaign   time.Duration
	statePath  string
	payloadMax int
	m          *metrics.Metrics

	mu   sync.Mutex
	seen map[string]time.Time
}

type Option func(*Notifier)

func WithCampaignCooldown(d time.Duration) Option { return func(n *Notifier) { n.campaign = d } }

func WithStateFile(path string) Option { return func(n *Notifier) { n.statePath = path } }

const maxRemembered = 5000

func NewNotifier(token, chatID, apiBase string, perMin, burst int, cooldown time.Duration,
	payloadMax int, m *metrics.Metrics, opts ...Option) *Notifier {
	if apiBase == "" {
		apiBase = defaultAPI
	}
	if m == nil {
		m = &metrics.Metrics{}
	}
	n := &Notifier{
		token:      token,
		chatID:     chatID,
		base:       strings.TrimRight(apiBase, "/"),
		client:     &http.Client{Timeout: 10 * time.Second},
		lim:        ratelimit.NewBucket(float64(perMin)/60.0, burst),
		cooldown:   cooldown,
		campaign:   cooldown,
		payloadMax: payloadMax,
		m:          m,
		seen:       make(map[string]time.Time),
	}
	for _, o := range opts {
		o(n)
	}
	n.load()
	return n
}

func (n *Notifier) Notify(ctx context.Context, ev *model.Event) (bool, error) {
	keys := n.keysFor(ev)
	if !n.reserve(keys) {
		n.m.AlertsDeduplicated.Add(1)
		return false, nil
	}
	if !n.lim.Allow() {
		n.release(keys)
		n.m.AlertsRateLimited.Add(1)
		return false, nil
	}
	if err := n.send(ctx, Format(ev, n.payloadMax), Buttons(ev)); err != nil {
		n.release(keys)
		n.m.AlertErrors.Add(1)
		return false, err
	}
	n.m.AlertsSent.Add(1)
	return true, nil
}

func (n *Notifier) SendText(ctx context.Context, text string) error {
	if err := n.send(ctx, text, nil); err != nil {
		n.m.AlertErrors.Add(1)
		return err
	}
	n.m.DigestsSent.Add(1)
	return nil
}

type keyExpiry struct {
	key string
	ttl time.Duration
}

func (n *Notifier) keysFor(ev *model.Event) []keyExpiry {
	var out []keyExpiry
	attack, campaign := fingerprints(ev)
	if n.cooldown > 0 {
		out = append(out, keyExpiry{attack, n.cooldown})
	}
	if n.campaign > 0 && campaign != "" {
		out = append(out, keyExpiry{campaign, n.campaign})
	}
	return out
}

func (n *Notifier) reserve(keys []keyExpiry) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	for _, k := range keys {
		if exp, ok := n.seen[k.key]; ok && now.Before(exp) {
			return false
		}
	}
	if len(keys) == 0 {
		return true
	}
	n.pruneLocked(now)
	for _, k := range keys {
		n.seen[k.key] = now.Add(k.ttl)
	}
	n.saveLocked()
	return true
}

func (n *Notifier) release(keys []keyExpiry) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, k := range keys {
		delete(n.seen, k.key)
	}
	n.saveLocked()
}

func (n *Notifier) pruneLocked(now time.Time) {
	if len(n.seen) < maxRemembered {
		return
	}
	for k, exp := range n.seen {
		if !now.Before(exp) {
			delete(n.seen, k)
		}
	}
	if len(n.seen) < maxRemembered {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(n.seen))
	for k, t := range n.seen {
		all = append(all, kv{k, t})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, e := range all[:len(all)-maxRemembered*4/5] {
		delete(n.seen, e.k)
	}
}

func (n *Notifier) load() {
	if n.statePath == "" {
		return
	}
	raw, err := os.ReadFile(n.statePath)
	if err != nil {
		return
	}
	var disk map[string]int64
	if json.Unmarshal(raw, &disk) != nil {
		return
	}
	now := time.Now()
	for k, exp := range disk {
		if t := time.Unix(exp, 0); now.Before(t) && len(n.seen) < maxRemembered {
			n.seen[k] = t
		}
	}
}

func (n *Notifier) saveLocked() {
	if n.statePath == "" {
		return
	}
	disk := make(map[string]int64, len(n.seen))
	for k, t := range n.seen {
		disk[k] = t.Unix()
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return
	}
	tmp := n.statePath + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) == nil {
		if os.Rename(tmp, n.statePath) != nil {
			_ = os.Remove(tmp)
		}
	}
}

func fingerprints(ev *model.Event) (attack, campaign string) {
	urls := append([]string{}, ev.IOCs.DownloadURLs...)
	if len(urls) == 0 {
		urls = append(urls, ev.IOCs.URLs...)
	}
	urls = append(urls, ev.IOCs.NFS...)
	sort.Strings(urls)
	var sums []string
	for _, d := range ev.Dropped {
		if d.SHA256 != "" {
			sums = append(sums, d.SHA256)
		}
	}
	sort.Strings(sums)
	payload := strings.Join(urls, ",") + "|" + strings.Join(sums, ",")

	h := sha256.New()
	h.Write([]byte("attack|" + ev.SrcIP + "|" + ev.Signature + "|" + payload))
	if len(urls) == 0 && len(sums) == 0 {
		t := strings.Join(ev.Commands, ";")
		if t == "" {
			t = ev.Text
		}
		if len(t) > 120 {
			t = t[:120]
		}
		h.Write([]byte("|" + t))
	}
	attack = hex.EncodeToString(h.Sum(nil)[:16])

	if len(urls) > 0 || len(sums) > 0 {
		c := sha256.Sum256([]byte("campaign|" + ev.Signature + "|" + payload))
		campaign = hex.EncodeToString(c[:16])
	}
	return attack, campaign
}

type tgResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (n *Notifier) send(ctx context.Context, text string, keyboard [][]Button) error {
	msg := map[string]any{
		"chat_id":                  n.chatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	}
	if len(keyboard) > 0 {
		msg["reply_markup"] = map[string]any{"inline_keyboard": keyboard}
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	endpoint := n.base + "/bot" + n.token + "/sendMessage"

	for attempt := 0; attempt < 2; attempt++ {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		req, err := http.NewRequestWithContext(rctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return errors.New("telegram: cannot build request")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client.Do(req)
		if err != nil {
			cancel()
			return redact(err)
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
		cancel()

		var tr tgResponse
		_ = json.Unmarshal(raw, &tr)
		if resp.StatusCode == http.StatusOK && tr.OK {
			return nil
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 &&
			tr.Parameters.RetryAfter > 0 && tr.Parameters.RetryAfter <= 10 {
			select {
			case <-time.After(time.Duration(tr.Parameters.RetryAfter) * time.Second):
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fmt.Errorf("telegram: HTTP %d: %s", resp.StatusCode, firstLine(tr.Description))
	}
	return errors.New("telegram: retries exhausted")
}

func redact(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("telegram: request failed: %w", ue.Err)
	}
	return errors.New("telegram: request failed")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return cutRunes(s, 200)
}
