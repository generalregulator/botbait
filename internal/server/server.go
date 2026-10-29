package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/generalregulator/botbait/internal/config"
	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/ratelimit"
)

type Handler interface {
	Handle(ctx context.Context, conn net.Conn, dstPort int)
}

type job struct {
	conn net.Conn
	port int
	addr netip.Addr
}

type Server struct {
	cfg *config.Config
	h   Handler
	lim *ratelimit.Limiter
	m   *metrics.Metrics
	log *slog.Logger

	mu     sync.Mutex
	perIP  map[netip.Addr]int
	active map[net.Conn]struct{}
}

func New(cfg *config.Config, h Handler, lim *ratelimit.Limiter, m *metrics.Metrics, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, h: h, lim: lim, m: m, log: log,
		perIP:  make(map[netip.Addr]int),
		active: make(map[net.Conn]struct{}),
	}
}

func (s *Server) Run(ctx context.Context) error {
	var listeners []net.Listener
	var lc net.ListenConfig
	for _, p := range s.cfg.Ports {
		ln, err := lc.Listen(ctx, "tcp", ":"+strconv.Itoa(p))
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return fmt.Errorf("listen on port %d: %w", p, err)
		}
		listeners = append(listeners, ln)
		s.log.Info("listening", "port", p, "addr", ln.Addr().String())
	}

	queue := make(chan job, s.cfg.QueueSize)
	var workers sync.WaitGroup
	for i := 0; i < s.cfg.MaxConns; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.worker(ctx, queue)
		}()
	}

	var acceptors sync.WaitGroup
	for i, ln := range listeners {
		acceptors.Add(1)
		go func(ln net.Listener, port int) {
			defer acceptors.Done()
			s.acceptLoop(ctx, ln, port, queue)
		}(ln, s.cfg.Ports[i])
	}

	<-ctx.Done()
	s.log.Info("shutdown: closing listeners")
	for _, ln := range listeners {
		_ = ln.Close()
	}
	acceptors.Wait()
	close(queue)
	s.expireActive()

	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(s.cfg.ShutdownTimeout):
		s.log.Warn("shutdown: timeout, force-closing sessions")
		s.closeActive()
		<-done
	}
	return nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, port int, queue chan<- job) {
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}

			if backoff == 0 {
				backoff = 20 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			s.log.Warn("accept error", "port", port, "err", err, "retry_in", backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			continue
		}
		backoff = 0

		addr, ok := remoteAddr(c)
		if !ok {
			_ = c.Close()
			continue
		}
		if !s.lim.Allow(addr) {
			s.m.ConnRateLimited.Add(1)
			_ = c.Close()
			continue
		}
		if !s.acquireIP(addr) {
			s.m.ConnPerIPLimited.Add(1)
			_ = c.Close()
			continue
		}
		select {
		case queue <- job{conn: c, port: port, addr: addr}:
			s.m.ConnAccepted.Add(1)
		default:
			s.releaseIP(addr)
			s.m.ConnQueueDropped.Add(1)
			_ = c.Close()
		}
	}
}

func (s *Server) worker(ctx context.Context, queue <-chan job) {
	for j := range queue {
		s.serve(ctx, j)
	}
}

func (s *Server) serve(ctx context.Context, j job) {
	defer s.releaseIP(j.addr)
	if ctx.Err() != nil {
		_ = j.conn.Close()
		return
	}
	s.track(j.conn)
	defer s.untrack(j.conn)
	defer func() {
		if r := recover(); r != nil {
			s.m.SessionPanics.Add(1)
			s.log.Error("session panic recovered", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			_ = j.conn.Close()
		}
	}()
	if ctx.Err() != nil {
		_ = j.conn.SetDeadline(time.Now())
	}
	s.h.Handle(ctx, j.conn, j.port)
	s.m.SessionsHandled.Add(1)
}

func remoteAddr(c net.Conn) (netip.Addr, bool) {
	ta, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(ta.IP)
	return a.Unmap(), ok
}

func (s *Server) acquireIP(a netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[a] >= s.cfg.MaxConnsPerIP {
		return false
	}
	s.perIP[a]++
	return true
}

func (s *Server) releaseIP(a netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[a] <= 1 {
		delete(s.perIP, a)
		return
	}
	s.perIP[a]--
}

func (s *Server) track(c net.Conn) {
	s.mu.Lock()
	s.active[c] = struct{}{}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

func (s *Server) expireActive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		_ = c.SetReadDeadline(time.Now())
	}
}

func (s *Server) closeActive() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.active {
		_ = c.Close()
	}
}
