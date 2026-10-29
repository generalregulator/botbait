package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/generalregulator/botbait/internal/model"
	"github.com/generalregulator/botbait/internal/parser"
	"github.com/generalregulator/botbait/internal/payloadstore"
	"github.com/generalregulator/botbait/internal/vfs"
)

const syncMaxChunk = 64 * 1024

type syncState struct {
	a  *adbSession
	st *adbStream

	buf []byte

	w       *payloadstore.Writer
	path    string
	modeStr string
	perm    uint32
	size    int64
	err     error
	active  bool
}

func newSyncState(a *adbSession, st *adbStream) *syncState { return &syncState{a: a, st: st} }

func (y *syncState) reply(id string, v uint32, payload []byte) {
	b := make([]byte, 8, 8+len(payload))
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], v)
	y.a.write(y.st, append(b, payload...))
}

func (y *syncState) fail(msg string) {
	y.reply("FAIL", uint32(len(msg)), []byte(msg))
}

func (y *syncState) feed(data []byte) {
	y.buf = append(y.buf, data...)
	for {
		if len(y.buf) < 8 {
			return
		}
		id := string(y.buf[:4])
		n := int(binary.LittleEndian.Uint32(y.buf[4:8]))

		switch id {
		case "DONE":

			y.buf = y.buf[8:]
			y.done()
			continue
		case "QUIT":
			y.buf = y.buf[8:]
			y.a.close(y.st, false)
			return
		}
		limit := syncMaxChunk
		if id != "DATA" {
			limit = 4096
		}
		if n < 0 || n > limit {
			y.fail("invalid sync request")
			y.buf = nil
			return
		}
		if len(y.buf) < 8+n {
			return
		}
		body := y.buf[8 : 8+n]
		y.buf = y.buf[8+n:]
		y.request(id, body)
		if _, alive := y.a.streams[y.st.id]; !alive {
			return
		}
	}
}

func (y *syncState) request(id string, body []byte) {
	s := y.a.s
	switch id {
	case "STAT":
		p := vfs.Clean("/", string(body))
		info, ok := y.fsStat(p)
		var mode, size, mtime uint32
		if ok {
			mode, size, mtime = fileMode(info), uint32(info.Size), uint32(info.MTime.Unix())
		}
		y.a.write(y.st, statReply(mode, size, mtime))
	case "LIST":
		p := vfs.Clean("/", string(body))
		s.line("ADB list %s", parser.Truncate(p, 256))
		y.list(p)
	case "RECV":
		p := vfs.Clean("/", string(body))
		s.line("ADB pull %s", parser.Truncate(p, 256))
		y.a.hasPull = true
		y.recv(p)
	case "SEND":
		y.begin(string(body))
	case "DATA":
		y.data(body)
	default:
		y.fail("unknown sync command")
	}
}

func statReply(mode, size, mtime uint32) []byte {
	b := make([]byte, 16)
	copy(b, "STAT")
	binary.LittleEndian.PutUint32(b[4:], mode)
	binary.LittleEndian.PutUint32(b[8:], size)
	binary.LittleEndian.PutUint32(b[12:], mtime)
	return b
}

func fileMode(i vfs.Info) uint32 {
	if i.IsDir {
		return 0o040000 | (i.Mode & 0o7777)
	}
	return 0o100000 | (i.Mode & 0o7777)
}

func (y *syncState) fsStat(p string) (vfs.Info, bool) { return y.a.s.ensureFS().Stat(p) }

func (y *syncState) list(p string) {
	fs := y.a.s.ensureFS()
	entries, err := fs.List(p)
	if err != nil {
		y.reply("DONE", 0, make([]byte, 12))
		return
	}
	for _, e := range entries {
		hdr := make([]byte, 20)
		copy(hdr, "DENT")
		binary.LittleEndian.PutUint32(hdr[4:], fileMode(e))
		binary.LittleEndian.PutUint32(hdr[8:], uint32(e.Size))
		binary.LittleEndian.PutUint32(hdr[12:], uint32(e.MTime.Unix()))
		binary.LittleEndian.PutUint32(hdr[16:], uint32(len(e.Name)))
		y.a.write(y.st, append(hdr, e.Name...))
	}
	y.reply("DONE", 0, make([]byte, 12))
}

func (y *syncState) recv(p string) {
	fs := y.a.s.ensureFS()
	info, ok := fs.Stat(p)
	switch {
	case !ok:
		y.fail("No such file or directory")
		return
	case info.IsDir:
		y.fail("Is a directory")
		return
	}
	data, err := fs.ReadFile(p)
	if err != nil {
		y.fail(err.Error())
		return
	}
	for len(data) > 0 {
		n := len(data)
		if n > syncMaxChunk {
			n = syncMaxChunk
		}
		y.reply("DATA", uint32(n), data[:n])
		data = data[n:]
	}
	y.reply("DONE", 0, nil)
}

func (y *syncState) begin(spec string) {
	s := y.a.s
	if y.active {
		y.finish(false)
	}
	path, modeStr := spec, "33188"
	if i := strings.LastIndexByte(spec, ','); i >= 0 {
		path, modeStr = spec[:i], spec[i+1:]
	}
	mode, err := strconv.ParseUint(modeStr, 10, 32)
	if err != nil {
		mode = 0o100644
	}
	y.path = parser.Truncate(parser.Sanitize([]byte(vfs.Clean("/", path)), 512), 512)
	y.perm = uint32(mode) & 0o7777
	y.modeStr = fmt.Sprintf("%04o", y.perm)
	y.size, y.err, y.w, y.active = 0, nil, nil, true
	y.a.hasPush = true
	y.a.updateAction()
	s.line("ADB push %s mode=%s", y.path, y.modeStr)

	switch {
	case len(s.drops) >= maxDrops:
		y.err = errPerSession
	case s.grantPush():
		w, err := s.h.store.NewWriter(s.h.cfg.MaxPushBytes)
		if err != nil {
			y.err = err
		} else {
			y.w = w
		}
	}
}

var errPerSession = errors.New("per-session file limit")

func (y *syncState) data(chunk []byte) {
	if !y.active {
		y.fail("DATA without SEND")
		return
	}
	y.size += int64(len(chunk))
	if y.w != nil && y.err == nil {
		if _, err := y.w.Write(chunk); err != nil {
			y.err = err
		}
	}
}

func (y *syncState) done() {
	if !y.active {
		return
	}
	y.finish(false)
	y.reply("OKAY", 0, nil)
}

func (y *syncState) finish(incomplete bool) {
	if !y.active {
		return
	}
	y.active = false
	s := y.a.s
	d := model.DroppedFile{
		Path: y.path, Via: payloadstore.SourceADBPush, Mode: y.modeStr, Size: y.size,
		Incomplete: incomplete,
	}
	w := y.w
	y.w = nil

	if w != nil && y.err == nil && w.Size() > 0 {
		res, err := w.Commit(payloadstore.Meta{
			Source: payloadstore.SourceADBPush, RemotePath: y.path, Mode: y.modeStr, SrcIP: s.ev.SrcIP,
		})
		if err == nil {
			d.Success, d.SHA256, d.Filename, d.FileType, d.Size = true, res.SHA256, res.Filename, res.FileType, res.Size
			d.Status = dropSaved
			if incomplete {
				d.Status = dropSavedPart
			}
		} else {
			y.err = err
		}
	} else if w != nil {
		w.Abort()
	}
	if !d.Success {
		switch {
		case errors.Is(y.err, payloadstore.ErrQuota):
			d.Status = dropQuota
		case errors.Is(y.err, payloadstore.ErrTooLarge):
			d.Status = dropTooLarge
		case errors.Is(y.err, errPerSession):
			d.Status = dropSessionCap
		case !s.captureEnabled():
			d.Status = dropDisabled
		case y.size == 0:
			d.Status = "Not Saved (Empty File)"
		default:
			d.Status = dropStoreFailed
		}
	}
	d.Executable = isExecutableType(d.FileType, y.perm)
	var load func() ([]byte, error)
	if d.Success && d.Filename != "" {
		load = s.pushLoader(d.Filename, d.Size)
	}
	_ = s.ensureFS().AddPushed(y.path, y.perm, y.size, load)
	s.recordDrop(d)
}
