package downloader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newDL(t *testing.T, mutate func(*Options)) *Downloader {
	t.Helper()
	o := Options{Dir: t.TempDir(), Timeout: 2 * time.Second, MaxBytes: 1024, MaxStorageBytes: 1 << 20,
		Workers: 2, AllowPrivate: true}
	if mutate != nil {
		mutate(&o)
	}
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestFetchStoresContentAddressedFile(t *testing.T) {
	payload := append([]byte("\x7fELF"), bytes.Repeat([]byte{0x41}, 200)...)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(payload) }))
	defer srv.Close()
	d := newDL(t, nil)

	res := d.Fetch(context.Background(), srv.URL+"/mips.sh", "203.0.113.9")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	if !res.Success || res.SHA256 != want || res.Filename != want+".bin" || res.FileType != "ELF" {
		t.Fatalf("unexpected result: %+v", res)
	}
	st, err := os.Stat(filepath.Join(d.store.Dir(), res.Filename))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o111 != 0 {
		t.Fatalf("captured file must not be executable, mode=%v", st.Mode())
	}
	if _, err := os.Stat(filepath.Join(d.store.Dir(), want+".json")); err != nil {
		t.Fatalf("metadata sidecar missing: %v", err)
	}

	if again := d.Fetch(context.Background(), srv.URL+"/mips.sh", "203.0.113.9"); !again.Cached || !again.Success {
		t.Fatalf("expected cached success, got %+v", again)
	}
}

func TestFetchSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {

		fl := w.(http.Flusher)
		for i := 0; i < 20; i++ {
			w.Write(bytes.Repeat([]byte{'A'}, 256))
			fl.Flush()
		}
	}))
	defer srv.Close()
	d := newDL(t, nil)
	res := d.Fetch(context.Background(), srv.URL+"/big", "198.51.100.1")
	if res.Status != StatusTooLarge || res.Success {
		t.Fatalf("got %+v", res)
	}
	entries, _ := os.ReadDir(d.store.Dir())
	if len(entries) != 0 {
		t.Fatalf("oversized download must leave no files, found %d", len(entries))
	}
}

func TestFetchTimeoutAndDeadLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	d := newDL(t, func(o *Options) { o.Timeout = 300 * time.Millisecond })

	start := time.Now()
	res := d.Fetch(context.Background(), srv.URL+"/slow", "198.51.100.1")
	if res.Status != StatusDead {
		t.Fatalf("timeout must map to %q, got %q", StatusDead, res.Status)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not enforced")
	}

	srv.Close()
	res = d.Fetch(context.Background(), srv.URL+"/gone", "198.51.100.1")
	if res.Status != StatusDead {
		t.Fatalf("dead link must map to %q, got %q", StatusDead, res.Status)
	}
}

func TestHTTPErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	res := newDL(t, nil).Fetch(context.Background(), srv.URL+"/x", "198.51.100.1")
	if res.Status != "Download Failed (HTTP 404)" {
		t.Fatalf("got %q", res.Status)
	}
}

func TestSSRFGuardBlocksLoopback(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit <- struct{}{}
		w.Write([]byte("secret"))
	}))
	defer srv.Close()
	d := newDL(t, func(o *Options) { o.AllowPrivate = false })
	res := d.Fetch(context.Background(), srv.URL+"/internal", "198.51.100.1")
	if res.Status != StatusBlocked {
		t.Fatalf("loopback target must be blocked, got %q", res.Status)
	}
	select {
	case <-hit:
		t.Fatal("request reached the internal server")
	default:
	}
}

func TestSSRFGuardBlocksRedirectToInternal(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("x")) }))
	defer internal.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redir.Close()

	d := newDL(t, func(o *Options) { o.AllowPrivate = false })
	res := d.Fetch(context.Background(), redir.URL+"/r", "198.51.100.1")
	if res.Success {
		t.Fatalf("redirect to loopback must not succeed: %+v", res)
	}
}

func TestSchemeAndURLValidation(t *testing.T) {
	d := newDL(t, nil)
	if r := d.Fetch(context.Background(), "ftp://203.0.113.1/x", "1.1.1.1"); r.Status != StatusBadScheme {
		t.Fatalf("ftp: %q", r.Status)
	}
	if r := d.Fetch(context.Background(), "http://", "1.1.1.1"); r.Status != StatusInvalidURL {
		t.Fatalf("empty host: %q", r.Status)
	}
}

func TestStorageQuota(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("0123456789")) }))
	defer srv.Close()
	d := newDL(t, func(o *Options) { o.MaxStorageBytes = 5 })
	d.store.SetUsedForTest(5)
	if r := d.Fetch(context.Background(), srv.URL+"/a", "1.1.1.1"); r.Status != StatusQuota {
		t.Fatalf("got %q", r.Status)
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.0.1": false, "172.16.5.5": false,
		"169.254.169.254": false, "100.64.1.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "224.0.0.1": false, "::ffff:10.0.0.1": false, "203.0.113.5": false,
	} {
		if got := IsPublic(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", ip, got, want)
		}
	}
}
