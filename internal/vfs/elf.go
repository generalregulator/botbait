package vfs

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/generalregulator/botbait/internal/profile"
)

type elfSpec struct {
	class64 bool
	big     bool
	machine uint16
	dyn     bool
}

const (
	emX86     = 3
	emMIPS    = 8
	emPPC     = 20
	emARM     = 40
	emSH      = 42
	emX86_64  = 62
	emAArch64 = 183
)

func elfSpecFor(p *profile.Profile) elfSpec {
	m := strings.ToLower(p.Kernel.Machine)
	e := elfSpec{machine: emARM, dyn: p.Kind == profile.KindAndroid}
	switch {
	case strings.HasPrefix(m, "aarch64"), strings.HasPrefix(m, "arm64"):
		e.class64, e.machine = true, emAArch64
	case strings.HasPrefix(m, "arm"):
	case strings.HasPrefix(m, "mips64"):
		e.class64, e.machine, e.big = true, emMIPS, !strings.HasSuffix(m, "el")
	case strings.HasPrefix(m, "mips"):
		e.machine, e.big = emMIPS, !strings.HasSuffix(m, "el")
	case m == "x86_64", m == "amd64":
		e.class64, e.machine = true, emX86_64
	case m == "i386", m == "i486", m == "i586", m == "i686", m == "x86":
		e.machine = emX86
	case strings.HasPrefix(m, "ppc"), strings.HasPrefix(m, "powerpc"):
		e.machine, e.big = emPPC, true
	case strings.HasPrefix(m, "sh"):
		e.machine = emSH
	}
	return e
}

func (e elfSpec) image(key string, size int64) []byte {
	hdr := 52
	if e.class64 {
		hdr = 64
	}
	if size < int64(hdr) {
		size = int64(hdr)
	}
	if size > 256<<10 {
		size = 256 << 10
	}
	b := make([]byte, size)
	var o binary.ByteOrder = binary.LittleEndian
	if e.big {
		o = binary.BigEndian
	}
	copy(b, "\x7fELF")
	b[4] = 1
	if e.class64 {
		b[4] = 2
	}
	b[5] = 1
	if e.big {
		b[5] = 2
	}
	b[6] = 1
	typ := uint16(2)
	if e.dyn {
		typ = 3
	}
	o.PutUint16(b[16:], typ)
	o.PutUint16(b[18:], e.machine)
	o.PutUint32(b[20:], 1)
	if e.class64 {
		o.PutUint64(b[24:], 0x1000+uint64(len(key)%7)*0x40)
		o.PutUint64(b[32:], 64)
		o.PutUint16(b[52:], 64)
		o.PutUint16(b[54:], 56)
		o.PutUint16(b[56:], 1)
		o.PutUint16(b[58:], 64)
	} else {
		o.PutUint32(b[24:], 0x8000+uint32(len(key)%7)*0x40)
		o.PutUint32(b[28:], 52)
		o.PutUint32(b[36:], 0x5000200)
		o.PutUint16(b[40:], 52)
		o.PutUint16(b[42:], 32)
		o.PutUint16(b[44:], 1)
		o.PutUint16(b[46:], 40)
	}

	var ctr [8]byte
	pos := hdr
	for i := uint64(0); pos < len(b); i++ {
		binary.LittleEndian.PutUint64(ctr[:], i)
		h := sha256.Sum256(append([]byte(key), ctr[:]...))
		pos += copy(b[pos:], h[:])
	}
	return b
}
