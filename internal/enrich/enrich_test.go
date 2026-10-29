package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLookupParsesCachesAndSkipsPrivate(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/8.8.8.8" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`{"status":"success","country":"United States","countryCode":"US","isp":"Google LLC","org":"","as":"AS15169 Google LLC","asname":"GOOGLE"}`))
	}))
	defer srv.Close()
	e := New(time.Second, srv.URL+"/")

	g := e.Lookup(context.Background(), "8.8.8.8")
	if !g.Resolved || g.Country != "United States" || g.ISP != "Google LLC" || g.ASN != "AS15169" || g.ASName != "GOOGLE" {
		t.Fatalf("bad geo: %+v", g)
	}
	_ = e.Lookup(context.Background(), "8.8.8.8")
	if hits.Load() != 1 {
		t.Fatalf("second lookup must be cached, hits=%d", hits.Load())
	}
	for _, ip := range []string{"10.0.0.1", "127.0.0.1", "not-an-ip"} {
		if g := e.Lookup(context.Background(), ip); g.Resolved {
			t.Errorf("%s must not be looked up", ip)
		}
	}
	if hits.Load() != 1 {
		t.Fatal("private/invalid addresses must never reach the API")
	}
}

func TestLookupTimeoutAndFailureFallBackToUnknown(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	start := time.Now()
	g := New(200*time.Millisecond, slow.URL+"/").Lookup(context.Background(), "8.8.4.4")
	if g.Resolved || g.Country != "Unknown" || time.Since(start) > time.Second {
		t.Fatalf("timeout not honoured: %+v after %s", g, time.Since(start))
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"fail","message":"reserved range"}`))
	}))
	defer fail.Close()
	if g := New(time.Second, fail.URL+"/").Lookup(context.Background(), "8.8.4.4"); g.Resolved {
		t.Fatalf("status=fail must yield Unknown: %+v", g)
	}
}
