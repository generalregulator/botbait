package e2e

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/ratelimit"
	"github.com/generalregulator/botbait/internal/server"
	"github.com/generalregulator/botbait/internal/session"
)

func BenchmarkHTTPSession(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := &config.Config{
		Ports: []int{port}, MaxConns: 256, MaxConnsPerIP: 1 << 20, QueueSize: 4096,
		ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, SessionTimeout: 5 * time.Second,
		MaxReadBytes: 64 * 1024, ShutdownTimeout: 5 * time.Second,
	}
	var events atomic.Int64
	sink := sinkFunc(func(*model.Event) { events.Add(1) })
	m := &metrics.Metrics{}
	srv := server.New(cfg, session.New(cfg, sink, m),
		ratelimit.New(1e9, 1<<30, 24, 64), m, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Run(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	req := []byte("GET /setup.cgi?next_file=netgear.cfg HTTP/1.0\r\nHost: x\r\nUser-Agent: bench\r\n\r\n")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 512)
		for pb.Next() {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				b.Error(err)
				return
			}
			c.Write(req)
			for {
				if _, err := c.Read(buf); err != nil {
					break
				}
			}
			c.Close()
		}
	})
	b.StopTimer()

	cancel()
	<-done
	if got := m.SessionPanics.Load(); got != 0 {
		b.Fatalf("panics: %d", got)
	}
	b.ReportMetric(float64(m.ConnQueueDropped.Load()+m.ConnRateLimited.Load()), "dropped")
}
