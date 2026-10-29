package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/generalregulator/botbait/internal/abuseipdb"
	"github.com/generalregulator/botbait/internal/alert"
	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/digest"
	"github.com/generalregulator/botbait/internal/downloader"
	"github.com/generalregulator/botbait/internal/enrich"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/pipeline"
	"github.com/generalregulator/botbait/internal/profile"
	"github.com/generalregulator/botbait/internal/ratelimit"
	"github.com/generalregulator/botbait/internal/server"
	"github.com/generalregulator/botbait/internal/session"
	"github.com/generalregulator/botbait/internal/store"
)

var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	healthcheck := flag.Bool("healthcheck", false, "probe the local health endpoint and exit (container HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print version and exit")
	envFile := flag.String("env-file", ".env", "optional KEY=VALUE file (real environment wins)")
	checkProfile := flag.String("check-profile", "", "validate a device profile (built-in name or JSON file), print a summary and exit")
	listProfiles := flag.Bool("list-profiles", false, "list the built-in device profiles and exit")
	digestPreview := flag.Bool("digest-preview", false, "print the weekly digest (last 7 days) to stdout (nothing is sent) and exit")
	digestNow := flag.Bool("digest-now", false, "send the weekly digest (last 7 days) to Telegram now and exit")
	flag.Parse()

	if *listProfiles {
		for _, n := range profile.Builtins() {
			fmt.Println(n)
		}
		return 0
	}
	if *checkProfile != "" {
		p, err := profile.Load(*checkProfile, "check")
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid profile:", err)
			return 1
		}
		fmt.Printf("ok: %s (%s) hostname=%s props=%d files=%d bins=%d commands=%d\n",
			p.Name, p.Kind, p.Hostname, len(p.Props), len(p.Files), len(p.Bins), len(p.Commands))
		return 0
	}

	if *showVersion {
		fmt.Println(version)
		return 0
	}
	if err := config.LoadDotEnv(*envFile); err != nil {
		fmt.Fprintln(os.Stderr, "env file:", err)
		return 2
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:\n"+err.Error())
		return 2
	}
	if *healthcheck {
		if err := metrics.Healthcheck(cfg.MetricsAddr); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			return 1
		}
		return 0
	}

	log := newLogger(cfg.LogLevel)
	if *digestPreview || *digestNow {
		return runDigest(cfg, log, *digestNow)
	}
	log.Info("starting honeypot", "version", version, "ports", cfg.Ports,
		"max_conns", cfg.MaxConns, "download", cfg.DownloadEnabled,
		"enrich", cfg.EnrichEnabled, "telegram", cfg.TelegramEnabled())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := &metrics.Metrics{}

	st, err := store.Open(cfg.LogDir)
	if err != nil {
		log.Error("cannot open event store", "err", err)
		return 1
	}
	defer st.Close()

	deps := pipeline.Deps{Cfg: cfg, Log: log, Metrics: m, Store: st}

	var samples *payloadstore.Store
	if cfg.DownloadEnabled || cfg.CapturePush {
		samples, err = payloadstore.New(cfg.PayloadDir, cfg.MaxStorageBytes)
		if err != nil {
			log.Error("cannot initialise payload store", "err", err)
			return 1
		}
	}
	if !cfg.CapturePush {
		log.Warn("file capture disabled (HP_CAPTURE_PUSH=false): adb push / echo droppers are recorded but not stored")
	}

	if cfg.DownloadEnabled {
		dl, err := downloader.New(downloader.Options{
			Store: samples, Timeout: cfg.DownloadTimeout, MaxBytes: cfg.MaxDownloadBytes,
			Workers: cfg.DownloadWorkers,
		})
		if err != nil {
			log.Error("cannot initialise payload downloader", "err", err)
			return 1
		}
		deps.Download = dl
	}
	if cfg.EnrichEnabled {
		deps.Enrich = enrich.New(cfg.EnrichTimeout, "")
	}
	if cfg.TelegramEnabled() {
		deps.Notifier = alert.NewNotifier(cfg.TelegramToken, cfg.TelegramChatID, "",
			cfg.TelegramPerMin, cfg.TelegramBurst, cfg.AlertCooldown, cfg.AlertPayloadMax, m,
			alert.WithCampaignCooldown(cfg.AlertCampaign), alert.WithStateFile(cfg.AlertStatePath()))
	} else {
		log.Warn("Telegram alerting disabled (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set)")
	}

	if cfg.AbuseEnabled() {
		deps.Abuse = abuseipdb.New(abuseipdb.Options{
			Key: cfg.AbuseKey, StatePath: cfg.AbuseStatePath(), Window: cfg.AbuseWindow, Metrics: m, Log: log,
		})
		deps.Abuse.Start()
		log.Info("AbuseIPDB reporting enabled", "window", cfg.AbuseWindow, "brute_force", cfg.AbuseBrute)
	}

	pipe := pipeline.New(deps)
	pipe.Start()

	if cfg.DigestEnabled && deps.Notifier != nil {
		dg := digestOptions(cfg, deps.Enrich)
		go dg.Run(ctx, func(c context.Context, text string) error {
			if err := deps.Notifier.SendText(c, text); err != nil {
				return err
			}
			m.DigestsSent.Add(1)
			return nil
		}, log)
	}

	lim := ratelimit.New(cfg.RateLimit, cfg.RateBurst, cfg.RatePrefix4, cfg.RatePrefix6)
	go lim.Run(ctx, time.Minute)

	go func() {
		if err := m.Serve(ctx, cfg.MetricsAddr); err != nil {
			log.Error("metrics endpoint failed", "err", err)
		}
	}()

	opts, err := personaOptions(cfg, log)
	if err != nil {
		log.Error("cannot load device profile", "err", err)
		return 2
	}
	if cfg.CapturePush {
		opts = append(opts, session.WithStore(samples))
	}
	srv := server.New(cfg, session.New(cfg, pipe, m, opts...), lim, m, log)
	exit := 0
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", "err", err)
		exit = 1
	}

	log.Info("draining pipeline")
	pipe.Shutdown(cfg.ShutdownTimeout)
	deps.Abuse.Stop(cfg.ShutdownTimeout)
	log.Info("stopped", "metrics", m.Snapshot())
	return exit
}

func personaOptions(cfg *config.Config, log *slog.Logger) ([]session.Option, error) {
	seed := cfg.ProfileSeed
	if seed == "" {
		var err error
		if seed, err = profile.PersistentSeed(cfg.LogDir); err != nil {
			log.Warn("cannot persist profile seed: device identifiers will change on restart", "err", err)
		}
	}
	p, err := profile.Load(cfg.Profile, seed)
	if err != nil {
		return nil, err
	}
	opts := []session.Option{session.WithProfile(p), session.WithWebSeed(seed)}
	tname := p.Name
	if cfg.TelnetProfile != "" && cfg.TelnetProfile != cfg.Profile {
		tp, err := profile.Load(cfg.TelnetProfile, seed)
		if err != nil {
			return nil, err
		}
		opts = append(opts, session.WithTelnetProfile(tp))
		tname = tp.Name
	}
	log.Info("device persona", "adb", p.Name, "telnet", tname, "kind", p.Kind)
	return opts, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func digestOptions(cfg *config.Config, en *enrich.Enricher) *digest.Options {
	day, _ := digest.ParseWeekday(cfg.DigestDay)
	o := &digest.Options{Dir: cfg.LogDir, Day: day, At: cfg.DigestAt, Top: cfg.DigestTop, EnrichMax: cfg.DigestEnrichMax}
	if en != nil {
		o.Resolve = en.LookupWait
	}
	return o
}

func runDigest(cfg *config.Config, log *slog.Logger, send bool) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var en *enrich.Enricher
	if cfg.EnrichEnabled {
		en = enrich.New(cfg.EnrichTimeout, "")
	}
	o := digestOptions(cfg, en)
	if !send {
		text, err := o.Build(ctx, time.Now().UTC())
		if err != nil {
			fmt.Fprintln(os.Stderr, "digest:", err)
			return 1
		}
		fmt.Println(text)
		return 0
	}
	if !cfg.TelegramEnabled() {
		fmt.Fprintln(os.Stderr, "digest: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not set")
		return 2
	}
	n := alert.NewNotifier(cfg.TelegramToken, cfg.TelegramChatID, "",
		cfg.TelegramPerMin, cfg.TelegramBurst, cfg.AlertCooldown, cfg.AlertPayloadMax, &metrics.Metrics{})
	if err := o.Send(ctx, n.SendText); err != nil {
		fmt.Fprintln(os.Stderr, "digest:", err)
		return 1
	}
	log.Info("digest sent")
	return 0
}
