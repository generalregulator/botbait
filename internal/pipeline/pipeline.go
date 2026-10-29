package pipeline

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/generalregulator/botbait/internal/abuseipdb"
	"github.com/generalregulator/botbait/internal/alert"
	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/downloader"
	"github.com/generalregulator/botbait/internal/enrich"
	"github.com/generalregulator/botbait/internal/ioc"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/mitre"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/store"
)

type Deps struct {
	Cfg      *config.Config
	Log      *slog.Logger
	Metrics  *metrics.Metrics
	Download *downloader.Downloader
	Enrich   *enrich.Enricher
	Notifier *alert.Notifier
	Store    *store.Store
	Abuse    *abuseipdb.Reporter
}

type Pipeline struct {
	Deps
	events chan *model.Event
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.RWMutex
	closed bool
}

func New(d Deps) *Pipeline {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{Deps: d, events: make(chan *model.Event, d.Cfg.EventQueue), ctx: ctx, cancel: cancel}
}

func (p *Pipeline) Start() {
	for i := 0; i < p.Cfg.PipelineWorkers; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for ev := range p.events {
				p.safeProcess(ev)
			}
		}()
	}
}

func (p *Pipeline) Submit(ev *model.Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.Metrics.EventsDropped.Add(1)
		return
	}
	select {
	case p.events <- ev:
		p.Metrics.EventsSubmitted.Add(1)
	default:
		p.Metrics.EventsDropped.Add(1)
	}
}

func (p *Pipeline) Shutdown(timeout time.Duration) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.events)
	}
	p.mu.Unlock()

	done := make(chan struct{})
	go func() { p.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		p.Log.Warn("pipeline shutdown timeout: cancelling in-flight work", "queued", len(p.events))
		p.cancel()
		<-done
	}
	p.cancel()
}

func (p *Pipeline) safeProcess(ev *model.Event) {
	defer func() {
		if r := recover(); r != nil {
			p.Log.Error("pipeline panic recovered", "event", ev.ID, "panic", r)
		}
	}()
	p.process(ev)
}

func (p *Pipeline) process(ev *model.Event) {

	text := ioc.StripHostHeader(ioc.Normalize(ev.Text))
	ev.IOCs = ioc.Extract(text)
	ev.Payload = parser.Truncate(ev.Text, p.Cfg.StorePayloadMax)
	ev.Techniques = mitre.Classify(mitre.Signals{
		Protocol:     ev.Protocol,
		Path:         ioc.Normalize(ev.HTTPPath),
		Text:         text,
		Credentials:  len(ev.Credentials),
		Signature:    ev.Signature,
		Strict:       ev.Persona != "",
		DownloadURLs: len(ev.IOCs.DownloadURLs) + len(ev.IOCs.NFS),
		Dropped:      executableDrops(ev),
	})
	for _, d := range ev.Dropped {
		if d.Success {
			p.Metrics.FilesCaptured.Add(1)
		} else {
			p.Metrics.FilesNotCaptured.Add(1)
		}
	}
	interesting := len(ev.Techniques) > 0 || !ev.IOCs.Empty() || len(ev.Credentials) > 0 || len(ev.Dropped) > 0
	if ev.Geo == (model.Geo{}) {
		ev.Geo = enrich.Unknown
	}

	var wg sync.WaitGroup
	if interesting && p.Enrich != nil && p.Cfg.EnrichEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev.Geo = p.Enrich.Lookup(p.ctx, ev.SrcIP)
		}()
	}
	ev.Downloads = p.capture(ev, &wg)
	wg.Wait()

	if p.Abuse != nil && p.reportWorthy(ev, text) {
		ev.AbuseReported = p.Abuse.Submit(ev)
	}

	if p.alertWorthy(ev) && p.Notifier != nil {
		sent, err := p.Notifier.Notify(p.ctx, ev)
		ev.AlertSent = sent
		if err != nil {
			p.Log.Warn("alert delivery failed", "event", ev.ID, "err", err)
		}
	}

	if p.Store != nil {
		if err := p.Store.Write(ev); err != nil {
			p.Log.Error("store write failed", "event", ev.ID, "err", err)
		}
	}
	p.Metrics.EventsProcessed.Add(1)

	if interesting {
		p.Log.Info("attack observed",
			"id", ev.ID, "src", ev.SrcIP, "port", ev.DstPort, "proto", ev.Protocol,
			"action", ev.Action, "mitre", strings.Join(ev.TechniqueIDs(), ","),
			"urls", len(ev.IOCs.URLs), "alert", ev.AlertSent)
	}
}

func executableDrops(ev *model.Event) int {
	n := 0
	for _, d := range ev.Dropped {
		if d.Executable {
			n++
		}
	}
	return n
}

func (p *Pipeline) capture(ev *model.Event, wg *sync.WaitGroup) []model.DownloadResult {
	urls := ev.IOCs.DownloadURLs
	if p.Download == nil || !p.Cfg.DownloadEnabled || len(urls) == 0 {
		return nil
	}
	limit := p.Cfg.MaxDownloadsPerEvent
	results := make([]model.DownloadResult, len(urls))
	for i, u := range urls {
		if i >= limit {
			results[i] = model.DownloadResult{URL: u, Status: "Download Skipped (Per-Event Limit)", Timestamp: time.Now().UTC()}
			p.Metrics.DownloadsSkipped.Add(1)
			continue
		}
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			r := p.Download.Fetch(p.ctx, u, ev.SrcIP)
			results[i] = r
			switch {
			case r.Success:
				p.Metrics.DownloadsOK.Add(1)
			case strings.HasPrefix(r.Status, "Download Skipped"):
				p.Metrics.DownloadsSkipped.Add(1)
			default:
				p.Metrics.DownloadsFailed.Add(1)
			}
		}(i, u)
	}
	return results
}

func (p *Pipeline) alertWorthy(ev *model.Event) bool {
	if ev.HasTechnique(mitre.T1190.ID) || ev.HasTechnique(mitre.T1059004.ID) ||
		ev.HasTechnique(mitre.T1105.ID) || ev.HasTechnique(mitre.T1496.ID) {
		return true
	}
	return p.Cfg.AlertOnBrute && ev.HasTechnique(mitre.T1110001.ID)
}

func (p *Pipeline) reportWorthy(ev *model.Event, text string) bool {
	if ev.HasTechnique(mitre.T1059004.ID) || ev.HasTechnique(mitre.T1105.ID) || ev.HasTechnique(mitre.T1496.ID) {
		return true
	}
	if ev.HasTechnique(mitre.T1190.ID) && (ev.Signature != "" || mitre.PayloadEvidence(text)) {
		return true
	}
	return p.Cfg.AbuseBrute && ev.HasTechnique(mitre.T1110001.ID)
}
