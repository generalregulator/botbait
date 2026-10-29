package ratelimit

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (b *bucket) idle(now time.Time, rate, burst float64) bool {
	return b.tokens+now.Sub(b.last).Seconds()*rate >= burst
}

type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	prefix4 int
	prefix6 int
	maxKeys int
	buckets map[netip.Prefix]*bucket
	now     func() time.Time
}

func New(rate float64, burst, prefix4, prefix6 int) *Limiter {
	return &Limiter{
		rate:    rate,
		burst:   float64(burst),
		prefix4: prefix4,
		prefix6: prefix6,
		maxKeys: 100_000,
		buckets: make(map[netip.Prefix]*bucket),
		now:     time.Now,
	}
}

func (l *Limiter) key(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := l.prefix6
	if a.Is4() {
		bits = l.prefix4
	}
	return netip.PrefixFrom(a, bits).Masked()
}

func (l *Limiter) Allow(addr netip.Addr) bool {
	k := l.key(addr)
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[k]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.sweepLocked(now)
			if len(l.buckets) >= l.maxKeys {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	return b.take(now, l.rate, l.burst)
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(l.now())
}

func (l *Limiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.idle(now, l.rate, l.burst) {
			delete(l.buckets, k)
		}
	}
}

func (l *Limiter) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.Sweep()
		}
	}
}

type Bucket struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	b     bucket
	now   func() time.Time
}

func NewBucket(ratePerSec float64, burst int) *Bucket {
	now := time.Now()
	return &Bucket{rate: ratePerSec, burst: float64(burst),
		b: bucket{tokens: float64(burst), last: now}, now: time.Now}
}

func (g *Bucket) Allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.b.take(g.now(), g.rate, g.burst)
}
