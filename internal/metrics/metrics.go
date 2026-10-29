package metrics

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

type Metrics struct {
	ConnAccepted       atomic.Uint64
	ConnRateLimited    atomic.Uint64
	ConnPerIPLimited   atomic.Uint64
	ConnQueueDropped   atomic.Uint64
	SessionsHandled    atomic.Uint64
	SessionPanics      atomic.Uint64
	ActiveSessions     atomic.Int64
	EventsSubmitted    atomic.Uint64
	EventsDropped      atomic.Uint64
	EventsProcessed    atomic.Uint64
	DownloadsOK        atomic.Uint64
	DownloadsFailed    atomic.Uint64
	DownloadsSkipped   atomic.Uint64
	FilesCaptured      atomic.Uint64
	FilesNotCaptured   atomic.Uint64
	AlertsSent         atomic.Uint64
	AlertsDeduplicated atomic.Uint64
	AlertsRateLimited  atomic.Uint64
	AlertErrors        atomic.Uint64
	DigestsSent        atomic.Uint64
	AbuseReported      atomic.Uint64
	AbuseErrors        atomic.Uint64
	AbuseSkipped       atomic.Uint64
}

func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"honeypot_connections_accepted_total":       int64(m.ConnAccepted.Load()),
		"honeypot_connections_rate_limited_total":   int64(m.ConnRateLimited.Load()),
		"honeypot_connections_per_ip_limited_total": int64(m.ConnPerIPLimited.Load()),
		"honeypot_connections_queue_dropped_total":  int64(m.ConnQueueDropped.Load()),
		"honeypot_sessions_handled_total":           int64(m.SessionsHandled.Load()),
		"honeypot_session_panics_total":             int64(m.SessionPanics.Load()),
		"honeypot_sessions_active":                  m.ActiveSessions.Load(),
		"honeypot_events_submitted_total":           int64(m.EventsSubmitted.Load()),
		"honeypot_events_dropped_total":             int64(m.EventsDropped.Load()),
		"honeypot_events_processed_total":           int64(m.EventsProcessed.Load()),
		"honeypot_downloads_ok_total":               int64(m.DownloadsOK.Load()),
		"honeypot_downloads_failed_total":           int64(m.DownloadsFailed.Load()),
		"honeypot_downloads_skipped_total":          int64(m.DownloadsSkipped.Load()),
		"honeypot_files_captured_total":             int64(m.FilesCaptured.Load()),
		"honeypot_files_not_captured_total":         int64(m.FilesNotCaptured.Load()),
		"honeypot_alerts_sent_total":                int64(m.AlertsSent.Load()),
		"honeypot_alerts_deduplicated_total":        int64(m.AlertsDeduplicated.Load()),
		"honeypot_alerts_rate_limited_total":        int64(m.AlertsRateLimited.Load()),
		"honeypot_alert_errors_total":               int64(m.AlertErrors.Load()),
		"honeypot_digests_sent_total":               int64(m.DigestsSent.Load()),
		"honeypot_abuseipdb_reports_total":          int64(m.AbuseReported.Load()),
		"honeypot_abuseipdb_errors_total":           int64(m.AbuseErrors.Load()),
		"honeypot_abuseipdb_skipped_total":          int64(m.AbuseSkipped.Load()),
	}
}

func (m *Metrics) Render(w io.Writer) {
	snap := m.Snapshot()
	names := make([]string, 0, len(snap))
	for k := range snap {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(w, "%s %d\n", k, snap[k])
	}
}

func (m *Metrics) Serve(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m.Render(w)
	})
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func Healthcheck(addr string) error {
	c := http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + addr + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: status %d", resp.StatusCode)
	}
	return nil
}
