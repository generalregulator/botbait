package payloadstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newStore(t *testing.T, max int64) *Store {
	t.Helper()
	s, err := New(t.TempDir(), max)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutContentAddressedAndPrivate(t *testing.T) {
	s := newStore(t, 1<<20)
	data := append([]byte("\x7fELF"), bytes.Repeat([]byte{1}, 100)...)
	r, err := s.Put(data, 1024, Meta{Source: SourceADBPush, SrcIP: "198.51.100.7", RemotePath: "/data/local/tmp/x", Mode: "0755"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if want := hex.EncodeToString(sum[:]); r.SHA256 != want || r.Filename != want+".bin" || !r.New || r.FileType != "ELF" {
		t.Fatalf("bad result %+v", r)
	}
	st, err := os.Stat(s.Path(r.Filename))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat=%v err=%v", st, err)
	}
}

func TestDedupeRecordsEverySighting(t *testing.T) {
	s := newStore(t, 1<<20)
	data := []byte("#!/bin/sh\necho hi\n")
	r1, _ := s.Put(data, 1024, Meta{Source: SourceDownload, URL: "http://a/x", SrcIP: "1.1.1.1"})
	used := s.Used()
	r2, err := s.Put(data, 1024, Meta{Source: SourceADBPush, SrcIP: "2.2.2.2", RemotePath: "/tmp/y"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.New || r2.SHA256 != r1.SHA256 {
		t.Fatalf("second copy must dedupe: %+v", r2)
	}
	b, err := os.ReadFile(filepath.Join(s.Dir(), r1.SHA256+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var sc sidecar
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	if sc.Count != 2 || len(sc.Sightings) != 2 || sc.Sightings[1].RemotePath != "/tmp/y" || sc.Sightings[1].Source != SourceADBPush {
		t.Fatalf("sidecar: %+v", sc)
	}

	if s.Used() <= used || s.Used()-used > 2048 {
		t.Fatalf("usage accounting off: before=%d after=%d", used, s.Used())
	}
	entries, _ := os.ReadDir(s.Dir())
	if len(entries) != 2 {
		t.Fatalf("want .bin + .json, got %d entries", len(entries))
	}
}

func TestSizeCapLeavesNoFiles(t *testing.T) {
	s := newStore(t, 1<<20)
	w, err := s.NewWriter(10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("0123456")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("789ABC")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	if _, err := w.Commit(Meta{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("commit after failure must fail, got %v", err)
	}
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Fatalf("leftover files: %v", entries)
	}
	if s.inflight.Load() != 0 {
		t.Fatalf("inflight leaked: %d", s.inflight.Load())
	}
}

func TestQuotaCountsInflightWriters(t *testing.T) {
	s := newStore(t, 100)
	w1, _ := s.NewWriter(100)
	w2, _ := s.NewWriter(100)
	if _, err := w1.Write(bytes.Repeat([]byte{'a'}, 60)); err != nil {
		t.Fatal(err)
	}

	if _, err := w2.Write(bytes.Repeat([]byte{'b'}, 60)); !errors.Is(err, ErrQuota) {
		t.Fatalf("want ErrQuota, got %v", err)
	}
	w1.Abort()
	w2.Abort()
	if s.inflight.Load() != 0 || s.Full() {
		t.Fatalf("state after abort: inflight=%d full=%v", s.inflight.Load(), s.Full())
	}
}

func TestEmptyRejectedAndFullStore(t *testing.T) {
	s := newStore(t, 10)
	if _, err := s.Put(nil, 10, Meta{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty: %v", err)
	}
	s.SetUsedForTest(10)
	if _, err := s.NewWriter(5); !errors.Is(err, ErrQuota) {
		t.Fatalf("full store must refuse writers, got %v", err)
	}
}

func TestStaleTempFilesRemovedAtStart(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, ".tmp-123")
	if err := os.WriteFile(stale, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale temp file survived start-up")
	}
}

func TestConcurrentWritersSameContent(t *testing.T) {
	s := newStore(t, 1<<20)
	data := []byte(strings.Repeat("payload-", 64))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Put(data, 4096, Meta{Source: SourceShell}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	entries, _ := os.ReadDir(s.Dir())
	if len(entries) != 2 {
		t.Fatalf("want exactly .bin and .json, got %d", len(entries))
	}
	if got := dirSize(s.Dir()); got != s.Used() {
		t.Fatalf("usage counter %d disagrees with disk %d", s.Used(), got)
	}
}

func TestSniff(t *testing.T) {
	for in, want := range map[string]string{
		"\x7fELFxxxx": "ELF", "#!/bin/sh": "script", "MZ\x90": "PE", "\x1f\x8b\x08": "gzip",
		"PK\x03\x04": "zip/apk/jar", "dex\n035": "dex", "hello": "data", "": "empty",
	} {
		if got := Sniff([]byte(in)); got != want {
			t.Errorf("Sniff(%q)=%s want %s", in, got, want)
		}
	}
}
