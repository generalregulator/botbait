package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/model"
)

func TestWriteJSONLConcurrentAndRotates(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 26, 23, 59, 0, 0, time.UTC)
	s.now = func() time.Time { return clock }

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := &model.Event{ID: "x", SrcIP: "203.0.113.1", Payload: "a & b <c>", Text: "must-not-be-stored"}
			if err := s.Write(ev); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	clock = clock.Add(2 * time.Minute)
	if err := s.Write(&model.Event{ID: "next-day"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
	if len(files) != 2 {
		t.Fatalf("expected 2 daily files, got %v", files)
	}
	f, _ := os.Open(filepath.Join(dir, "events-2026-10-26.jsonl"))
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
		line := sc.Text()
		if !json.Valid([]byte(line)) {
			t.Fatalf("interleaved/invalid line: %q", line)
		}
		if !strings.Contains(line, `"payload":"a & b <c>"`) {
			t.Fatalf("HTML must not be escaped in the log: %s", line)
		}
		if strings.Contains(line, "must-not-be-stored") {
			t.Fatal("analysis-only Text field leaked into the log")
		}
	}
	if n != 50 {
		t.Fatalf("expected 50 lines, got %d", n)
	}
}
