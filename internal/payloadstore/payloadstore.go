package payloadstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SourceDownload = "http-download"
	SourceADBPush  = "adb-sync-push"
	SourceShell    = "shell-write"
)

var (
	ErrTooLarge = errors.New("payloadstore: file exceeds size limit")

	ErrQuota = errors.New("payloadstore: storage quota reached")

	ErrEmpty = errors.New("payloadstore: empty file")

	ErrClosed = errors.New("payloadstore: writer closed")

	tmpPrefix = ".tmp-"
)

const maxSightings = 50

type Meta struct {
	Source      string
	URL         string
	RemotePath  string
	Mode        string
	SrcIP       string
	ContentType string
}

type Result struct {
	SHA256   string
	Filename string
	FileType string
	Size     int64
	New      bool
}

type Sighting struct {
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	SourceIP    string    `json:"source_ip,omitempty"`
	URL         string    `json:"url,omitempty"`
	RemotePath  string    `json:"remote_path,omitempty"`
	Mode        string    `json:"mode,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
}

type sidecar struct {
	SHA256    string     `json:"sha256"`
	Size      int64      `json:"size"`
	FileType  string     `json:"file_type"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  time.Time  `json:"last_seen"`
	Count     int        `json:"sightings_total"`
	Sightings []Sighting `json:"sightings"`

	SourceIP string `json:"source_ip,omitempty"`
	URL      string `json:"url,omitempty"`
}

type Store struct {
	dir      string
	max      int64
	stored   atomic.Int64
	inflight atomic.Int64
	mu       sync.Mutex
}

func New(dir string, maxStorage int64) (*Store, error) {
	if dir == "" || maxStorage <= 0 {
		return nil, errors.New("payloadstore: invalid options")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("payloadstore: create dir: %w", err)
	}
	s := &Store{dir: dir, max: maxStorage}
	s.cleanTemp()
	s.stored.Store(dirSize(dir))
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Used() int64 { return s.stored.Load() }

func (s *Store) Full() bool { return s.stored.Load()+s.inflight.Load() >= s.max }

func (s *Store) SetUsedForTest(n int64) { s.stored.Store(n) }

func (s *Store) Path(filename string) string { return filepath.Join(s.dir, filepath.Base(filename)) }

type Writer struct {
	s      *Store
	f      *os.File
	name   string
	h      hash.Hash
	head   []byte
	n      int64
	max    int64
	err    error
	closed bool
}

func (s *Store) NewWriter(maxBytes int64) (*Writer, error) {
	if maxBytes <= 0 {
		return nil, ErrTooLarge
	}
	if s.Full() {
		return nil, ErrQuota
	}
	f, err := os.CreateTemp(s.dir, tmpPrefix+"*")
	if err != nil {
		return nil, fmt.Errorf("payloadstore: temp file: %w", err)
	}
	return &Writer{s: s, f: f, name: f.Name(), h: sha256.New(), max: maxBytes}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, ErrClosed
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.n+int64(len(p)) > w.max {
		w.err = ErrTooLarge
		return 0, w.err
	}
	if w.s.stored.Load()+w.s.inflight.Load()+int64(len(p)) > w.s.max {
		w.err = ErrQuota
		return 0, w.err
	}
	n, err := w.f.Write(p)
	w.n += int64(n)
	w.s.inflight.Add(int64(n))
	w.h.Write(p[:n])
	if room := 16 - len(w.head); room > 0 {
		if room > n {
			room = n
		}
		w.head = append(w.head, p[:room]...)
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *Writer) Size() int64 { return w.n }

func (w *Writer) Err() error { return w.err }

func (w *Writer) Abort() {
	if w.closed {
		return
	}
	w.closed = true
	w.s.inflight.Add(-w.n)
	_ = w.f.Close()
	_ = os.Remove(w.name)
}

func (w *Writer) Commit(m Meta) (Result, error) {
	if w.closed {
		return Result{}, ErrClosed
	}
	if w.err != nil {
		w.Abort()
		return Result{}, w.err
	}
	if w.n == 0 {
		w.Abort()
		return Result{}, ErrEmpty
	}
	w.closed = true
	w.s.inflight.Add(-w.n)
	if err := w.f.Close(); err != nil {
		_ = os.Remove(w.name)
		return Result{}, err
	}

	sum := hex.EncodeToString(w.h.Sum(nil))
	res := Result{SHA256: sum, Filename: sum + ".bin", FileType: Sniff(w.head), Size: w.n}
	final := filepath.Join(w.s.dir, res.Filename)

	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if _, err := os.Stat(final); err == nil {
		_ = os.Remove(w.name)
	} else {
		if err := os.Rename(w.name, final); err != nil {
			_ = os.Remove(w.name)
			return Result{}, fmt.Errorf("payloadstore: store: %w", err)
		}
		_ = os.Chmod(final, 0o600)
		w.s.stored.Add(w.n)
		res.New = true
	}
	w.s.recordSightingLocked(res, m)
	return res, nil
}

func (s *Store) Put(data []byte, maxBytes int64, m Meta) (Result, error) {
	w, err := s.NewWriter(maxBytes)
	if err != nil {
		return Result{}, err
	}
	if _, err := w.Write(data); err != nil {
		w.Abort()
		return Result{}, err
	}
	return w.Commit(m)
}

func (s *Store) recordSightingLocked(r Result, m Meta) {
	path := filepath.Join(s.dir, r.SHA256+".json")
	now := time.Now().UTC()
	var sc sidecar
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &sc)
	}
	if sc.SHA256 == "" {
		sc = sidecar{SHA256: r.SHA256, Size: r.Size, FileType: r.FileType, FirstSeen: now,
			SourceIP: m.SrcIP, URL: m.URL}
	}
	sc.LastSeen = now
	sc.Count++
	if len(sc.Sightings) < maxSightings {
		sc.Sightings = append(sc.Sightings, Sighting{
			Timestamp: now, Source: m.Source, SourceIP: m.SrcIP, URL: m.URL,
			RemotePath: m.RemotePath, Mode: m.Mode, ContentType: m.ContentType,
		})
	}
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		old := int64(0)
		if st, err := os.Stat(path); err == nil {
			old = st.Size()
		}
		if os.Rename(tmp, path) == nil {
			s.stored.Add(int64(len(b)) - old)
		} else {
			_ = os.Remove(tmp)
		}
	}
}

func Sniff(b []byte) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "\x7fELF":
		return "ELF"
	case len(b) >= 2 && string(b[:2]) == "#!":
		return "script"
	case len(b) >= 2 && string(b[:2]) == "MZ":
		return "PE"
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return "gzip"
	case len(b) >= 4 && string(b[:4]) == "PK\x03\x04":
		return "zip/apk/jar"
	case len(b) >= 4 && string(b[:4]) == "dex\n":
		return "dex"
	case len(b) > 0:
		return "data"
	}
	return "empty"
}

func (s *Store) cleanTemp() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, tmpPrefix) || strings.HasSuffix(n, ".json.tmp") {
			_ = os.Remove(filepath.Join(s.dir, n))
		}
	}
}

func dirSize(dir string) int64 {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total
}
