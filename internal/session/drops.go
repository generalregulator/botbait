package session

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/shell"
	"github.com/generalregulator/botbait/internal/vfs"
)

const maxDrops = 8

const maxPushReadBytes = 64 << 20

const (
	dropSaved       = "Saved"
	dropSavedPart   = "Saved (Incomplete Transfer)"
	dropDisabled    = "Not Saved (Capture Disabled)"
	dropQuota       = "Not Saved (Storage Quota Reached)"
	dropTooLarge    = "Not Saved (Size Limit Exceeded)"
	dropSessionCap  = "Not Saved (Per-Session Limit)"
	dropStoreFailed = "Not Saved (Storage Error)"
)

func (s *sess) captureEnabled() bool { return s.h.store != nil && s.h.cfg.CapturePush }

func (s *sess) newShell() *shell.Shell {
	prof := s.h.adbProf
	if s.telnetMode {
		prof = s.h.telProf
	}
	return shell.New(prof, s.ensureFS(), shell.Options{Start: s.h.start})
}

func (s *sess) ensureFS() *vfs.FS {
	if s.fs == nil {
		base := s.h.adbBase
		if s.telnetMode {
			base = s.h.telBase
		}
		s.fs = base.New(vfs.DefaultLimits)
	}
	return s.fs
}

func (s *sess) grantPush() bool {
	if !s.captureEnabled() {
		return false
	}
	if !s.pushGrant {
		s.pushGrant = true

		s.budget += int(s.h.cfg.MaxPushBytes) + int(s.h.cfg.MaxPushBytes/256) + 64<<10
		if d := s.ev.Timestamp.Add(s.h.cfg.PushSessionTimeout); d.After(s.end) {
			s.end = d
		}
	}
	return true
}

func isExecutableType(ft string, mode uint32) bool {
	switch ft {
	case "ELF", "script", "PE", "dex", "zip/apk/jar", "gzip":
		return true
	}
	return mode&0o111 != 0
}

func (s *sess) recordDrop(d model.DroppedFile) {
	if len(s.drops) >= maxDrops {
		return
	}
	d.Timestamp = time.Now().UTC()
	s.drops = append(s.drops, d)
	if d.Success {
		s.line("[dropped] %s via %s mode=%s size=%d type=%s sha256=%s", d.Path, d.Via, d.Mode, d.Size, d.FileType, d.SHA256)
	} else {
		s.line("[dropped] %s via %s mode=%s (%s)", d.Path, d.Via, d.Mode, d.Status)
	}
}

func (s *sess) storeBytes(path, via, mode string, modeBits uint32, data []byte) model.DroppedFile {
	sum := sha256.Sum256(data)
	ft := payloadstore.Sniff(data)
	d := model.DroppedFile{
		Path: path, Via: via, Mode: mode, Size: int64(len(data)), FileType: ft,
		SHA256: hex.EncodeToString(sum[:]), Executable: isExecutableType(ft, modeBits),
	}
	if !s.captureEnabled() {
		d.Status = dropDisabled
		return d
	}
	res, err := s.h.store.Put(data, int64(len(data)), payloadstore.Meta{
		Source: via, RemotePath: path, Mode: mode, SrcIP: s.ev.SrcIP,
	})
	switch {
	case err == nil:
		d.Status, d.Success, d.Filename = dropSaved, true, res.Filename
	case errors.Is(err, payloadstore.ErrQuota):
		d.Status = dropQuota
	case errors.Is(err, payloadstore.ErrTooLarge):
		d.Status = dropTooLarge
	default:
		d.Status = dropStoreFailed
	}
	return d
}

func (s *sess) finishDrops() {
	if s.fs == nil {
		return
	}
	seen := map[string]bool{}
	for _, d := range s.drops {
		seen[d.SHA256] = true
	}
	for _, c := range s.fs.Created() {
		if len(c.Data) == 0 {
			continue
		}
		sum := sha256.Sum256(c.Data)
		key := hex.EncodeToString(sum[:])
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(s.drops) >= maxDrops {
			break
		}
		s.recordDrop(s.storeBytes(c.Path, payloadstore.SourceShell, fmt.Sprintf("%04o", c.Mode), c.Mode, c.Data))
	}
}

func (s *sess) recordRevealed(sh *shell.Shell, seen *int) {
	rev := sh.Revealed()
	for ; *seen < len(rev); *seen++ {
		s.line("[script] %s", rev[*seen])
	}
}

func (s *sess) pushLoader(filename string, size int64) func() ([]byte, error) {
	p := filepath.Join(s.h.store.Dir(), filepath.Base(filename))
	return func() ([]byte, error) {
		if size <= 0 || s.pushRead+size > maxPushReadBytes {
			return nil, nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, nil
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, size+1))
		if err != nil || int64(len(b)) != size {
			return nil, nil
		}
		s.pushRead += size
		return b, nil
	}
}
