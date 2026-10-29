package enrich

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/generalregulator/botbait/internal/downloader"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/ratelimit"
)

const defaultBase = "http://ip-api.com/json/"

type Enricher struct {
	client  *http.Client
	base    string
	timeout time.Duration
	lim     *ratelimit.Bucket

	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	geo model.Geo
	at  time.Time
}

const (
	cacheTTL = 24 * time.Hour
	cacheMax = 10_000
)

func New(timeout time.Duration, baseURL string) *Enricher {
	if baseURL == "" {
		baseURL = defaultBase
	}
	return &Enricher{
		client:  &http.Client{Timeout: timeout},
		base:    baseURL,
		timeout: timeout,
		lim:     ratelimit.NewBucket(40.0/60.0, 5),
		cache:   make(map[string]entry),
	}
}

var Unknown = model.Geo{Country: "Unknown", ISP: "Unknown"}

type apiResp struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	AS          string `json:"as"`
	ASName      string `json:"asname"`
}

func (e *Enricher) Lookup(ctx context.Context, ip string) model.Geo {
	return e.lookup(ctx, ip, false)
}

func (e *Enricher) lookup(ctx context.Context, ip string, wait bool) model.Geo {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !downloader.IsPublic(addr) {
		return Unknown
	}
	if g, ok := e.cached(ip); ok {
		return g
	}
	if !e.lim.Allow() {
		if !wait || !e.waitToken(ctx) {
			return Unknown
		}
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	q := url.Values{"fields": {"status,country,countryCode,isp,org,as,asname"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		e.base+url.PathEscape(ip)+"?"+q.Encode(), nil)
	if err != nil {
		return Unknown
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return Unknown
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Unknown
	}
	var r apiResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil || r.Status != "success" {
		return Unknown
	}

	g := model.Geo{
		Country:     orUnknown(r.Country),
		CountryCode: r.CountryCode,
		ISP:         orUnknown(firstNonEmpty(r.ISP, r.Org)),
		ASName:      r.ASName,
		Resolved:    true,
	}
	if f := strings.Fields(r.AS); len(f) > 0 && strings.HasPrefix(strings.ToUpper(f[0]), "AS") {
		g.ASN = strings.ToUpper(f[0])
	}
	e.store(ip, g)
	return g
}

func (e *Enricher) LookupWait(ctx context.Context, ip string) model.Geo {
	return e.lookup(ctx, ip, true)
}

func (e *Enricher) waitToken(ctx context.Context) bool {
	for i := 0; i < 400; i++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
		if e.lim.Allow() {
			return true
		}
	}
	return false
}

func (e *Enricher) cached(ip string) (model.Geo, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, ok := e.cache[ip]
	if !ok || time.Since(c.at) > cacheTTL {
		return model.Geo{}, false
	}
	return c.geo, true
}

func (e *Enricher) store(ip string, g model.Geo) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.cache) >= cacheMax {
		for k, v := range e.cache {
			if time.Since(v.at) > cacheTTL {
				delete(e.cache, k)
			}
		}
		for k := range e.cache {
			if len(e.cache) < cacheMax/2 {
				break
			}
			delete(e.cache, k)
		}
	}
	e.cache[ip] = entry{geo: g, at: time.Now()}
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "Unknown"
	}
	return s
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
