package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/generalregulator/botbait/internal/model"
)

type Store struct {
	dir string
	now func() time.Time

	mu  sync.Mutex
	f   *os.File
	day string
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{dir: dir, now: time.Now}, nil
}

func (s *Store) Write(ev *model.Event) error {

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		return err
	}
	line := buf.Bytes()
	var err error

	s.mu.Lock()
	defer s.mu.Unlock()
	day := s.now().UTC().Format("2006-01-02")
	if s.f == nil || day != s.day {
		if s.f != nil {
			_ = s.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(s.dir, "events-"+day+".jsonl"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			s.f = nil
			return err
		}
		s.f, s.day = f, day
	}
	_, err = s.f.Write(line)
	return err
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
