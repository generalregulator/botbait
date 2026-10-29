package downloader

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/payloadstore"
)

const (
	StatusOK          = "Downloaded"
	StatusDead        = "Download Failed (Dead Link or Timeout)"
	StatusTooLarge    = "Download Aborted (Size Limit Exceeded)"
	StatusQuota       = "Download Skipped (Storage Quota Reached)"
	StatusBlocked     = "Download Skipped (Blocked Address)"
	StatusBadScheme   = "Download Skipped (Unsupported Scheme)"
	StatusInvalidURL  = "Download Skipped (Invalid URL)"
	StatusInterrupted = "Download Interrupted (Shutdown)"
)

var ErrBlockedAddr = errors.New("destination address is not publicly routable")

type Options struct {
	Store           *payloadstore.Store
	Dir             string
	Timeout         time.Duration
	MaxBytes        int64
	MaxStorageBytes int64
	Workers         int
	CacheTTL        time.Duration
	UserAgent       string

	AllowPrivate bool
}

type cached struct {
	res model.DownloadResult
	at  time.Time
}

type Downloader struct {
	opts   Options
	client *http.Client
	sem    chan struct{}
	store  *payloadstore.Store

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]chan struct{}
}

func New(o Options) (*Downloader, error) {
	if o.Timeout <= 0 || o.MaxBytes <= 0 || o.Workers <= 0 || (o.Store == nil && o.Dir == "") {
		return nil, errors.New("downloader: invalid options")
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 10 * time.Minute
	}
	if o.UserAgent == "" {
		o.UserAgent = "Wget/1.21.3"
	}
	if o.Store == nil {
		st, err := payloadstore.New(o.Dir, o.MaxStorageBytes)
		if err != nil {
			return nil, fmt.Errorf("downloader: %w", err)
		}
		o.Store = st
	}
	d := &Downloader{
		opts:     o,
		sem:      make(chan struct{}, o.Workers),
		store:    o.Store,
		cache:    make(map[string]cached),
		inflight: make(map[string]chan struct{}),
	}

	dialer := &net.Dialer{Timeout: o.Timeout, Control: d.guard}
	d.client = &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			DisableKeepAlives:      true,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 << 10,
			TLSHandshakeTimeout:    o.Timeout,
			ResponseHeaderTimeout:  o.Timeout,

			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}, //nolint:gosec
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	return d, nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func IsPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (d *Downloader) guard(_, address string, _ syscall.RawConn) error {
	if d.opts.AllowPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ErrBlockedAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !IsPublic(ip) {
		return ErrBlockedAddr
	}
	return nil
}

func (d *Downloader) Fetch(ctx context.Context, rawURL, srcIP string) model.DownloadResult {
	start := time.Now()
	res := model.DownloadResult{URL: rawURL, Timestamp: start.UTC()}
	finish := func(status string) model.DownloadResult {
		res.Status = status
		res.Success = status == StatusOK
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return finish(StatusInvalidURL)
	}
	if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
		return finish(StatusBadScheme)
	}

	for {
		d.mu.Lock()
		if c, ok := d.cache[rawURL]; ok && time.Since(c.at) < d.opts.CacheTTL {
			d.mu.Unlock()
			r := c.res
			r.Cached = true
			return r
		}
		ch, busy := d.inflight[rawURL]
		if !busy {
			d.inflight[rawURL] = make(chan struct{})
			d.mu.Unlock()
			break
		}
		d.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return finish(StatusInterrupted)
		}
	}
	defer func() {
		d.mu.Lock()
		close(d.inflight[rawURL])
		delete(d.inflight, rawURL)
		d.mu.Unlock()
	}()

	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	case <-ctx.Done():
		return finish(StatusInterrupted)
	}

	out := d.fetch(ctx, u, srcIP, &res)
	r := finish(out)

	d.mu.Lock()
	d.cache[rawURL] = cached{res: r, at: time.Now()}
	d.pruneLocked()
	d.mu.Unlock()
	return r
}

func (d *Downloader) fetch(ctx context.Context, u *url.URL, srcIP string, res *model.DownloadResult) string {
	if d.store.Full() {
		return StatusQuota
	}
	rctx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return StatusInvalidURL
	}
	req.Header.Set("User-Agent", d.opts.UserAgent)
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlockedAddr) {
			return StatusBlocked
		}
		if ctx.Err() != nil {
			return StatusInterrupted
		}
		return StatusDead
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Sprintf("Download Failed (HTTP %d)", resp.StatusCode)
	}
	if resp.ContentLength > d.opts.MaxBytes {
		return StatusTooLarge
	}
	res.ContentType = resp.Header.Get("Content-Type")

	w, err := d.store.NewWriter(d.opts.MaxBytes)
	if err != nil {
		return StatusQuota
	}

	if _, err := io.Copy(w, io.LimitReader(resp.Body, d.opts.MaxBytes+1)); err != nil {
		w.Abort()
		switch {
		case errors.Is(err, payloadstore.ErrTooLarge):
			return StatusTooLarge
		case errors.Is(err, payloadstore.ErrQuota):
			return StatusQuota
		case ctx.Err() != nil:
			return StatusInterrupted
		}
		return StatusDead
	}
	stored, err := w.Commit(payloadstore.Meta{
		Source: payloadstore.SourceDownload, URL: u.String(), SrcIP: srcIP, ContentType: res.ContentType,
	})
	switch {
	case errors.Is(err, payloadstore.ErrEmpty):
		return StatusDead
	case err != nil:
		return StatusQuota
	}
	res.SHA256 = stored.SHA256
	res.Filename = stored.Filename
	res.Size = stored.Size
	res.FileType = stored.FileType
	return StatusOK
}

func (d *Downloader) pruneLocked() {
	if len(d.cache) < 4096 {
		return
	}
	for k, c := range d.cache {
		if time.Since(c.at) >= d.opts.CacheTTL {
			delete(d.cache, k)
		}
	}
	for k := range d.cache {
		if len(d.cache) < 2048 {
			break
		}
		delete(d.cache, k)
	}
}
