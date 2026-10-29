package digest

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

type Options struct {
	Dir       string
	Day       time.Weekday
	At        string
	Top       int
	EnrichMax int
	Resolve   Resolver
	Now       func() time.Time
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

func (o *Options) Build(ctx context.Context, to time.Time) (string, error) {
	d, err := Collect(o.Dir, to.Add(-Window), to)
	if err != nil {
		return "", err
	}
	d.Enrich(ctx, o.Resolve, o.EnrichMax)
	return d.Format(o.Top), nil
}

func (o *Options) Send(ctx context.Context, send func(context.Context, string) error) error {
	text, err := o.Build(ctx, o.now())
	if err != nil {
		return err
	}
	return send(ctx, text)
}

func ParseWeekday(s string) (time.Weekday, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for d := time.Sunday; d <= time.Saturday; d++ {
		name := strings.ToLower(d.String())
		if s == name || s == name[:3] {
			return d, true
		}
	}
	return 0, false
}

func NextRun(now time.Time, day time.Weekday, at string) time.Time {
	t, err := time.Parse("15:04", at)
	if err != nil {
		t, _ = time.Parse("15:04", "09:00")
	}
	now = now.UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, time.UTC)
	next = next.AddDate(0, 0, (int(day)-int(next.Weekday())+7)%7)
	if !next.After(now) {
		next = next.AddDate(0, 0, 7)
	}
	return next
}

func (o *Options) Run(ctx context.Context, send func(context.Context, string) error, log *slog.Logger) {
	for {
		next := NextRun(o.now(), o.Day, o.At)
		log.Info("weekly digest scheduled", "at", next.Format(time.RFC3339))
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		for attempt := 1; attempt <= 3; attempt++ {
			err := o.Send(ctx, send)
			if err == nil {
				log.Info("weekly digest sent")
				break
			}
			log.Warn("weekly digest failed", "attempt", attempt, "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Minute):
			}
		}
	}
}
