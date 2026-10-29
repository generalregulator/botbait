package shell

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

func cmdDd(c *cctx) int {
	var in, of string
	ibs, obs, count, skip, seek := 512, 0, -1, 0, 0
	conv := map[string]bool{}
	num := func(v string) int {
		mult := 1
		for _, suf := range []struct {
			s string
			m int
		}{{"k", 1024}, {"K", 1024}, {"kB", 1000}, {"M", 1 << 20}, {"MB", 1000 * 1000}, {"b", 512}, {"w", 2}} {
			if strings.HasSuffix(v, suf.s) {
				mult, v = suf.m, strings.TrimSuffix(v, suf.s)
				break
			}
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1<<26 {
			return -1
		}
		return n * mult
	}
	for _, a := range c.args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			c.errorf("dd: unknown operand %s\n", a)
			return 1
		}
		switch k {
		case "if":
			in = v
		case "of":
			of = v
		case "bs":
			ibs = num(v)
			obs = ibs
		case "ibs":
			ibs = num(v)
		case "obs":
			obs = num(v)
		case "count":
			count = num(v)
		case "skip":
			skip = num(v)
		case "seek":
			seek = num(v)
		case "conv":
			for _, f := range strings.Split(v, ",") {
				conv[f] = true
			}
		}
		if ibs < 0 || count < -1 && k == "count" || skip < 0 || seek < 0 {
			c.errorf("dd: invalid number '%s'\n", v)
			return 1
		}
	}
	if ibs == 0 {
		ibs = 512
	}
	if obs == 0 {
		obs = ibs
	}
	var data []byte
	if in == "" {
		data = c.in
	} else {
		b, err := c.s.fs.ReadFile(c.s.abs(in))
		if err != nil {
			c.errorf("dd: can't open '%s': %s\n", in, err.Error())
			return 1
		}
		data = b
	}
	if off := skip * ibs; off >= len(data) {
		data = nil
	} else {
		data = data[off:]
	}
	if count >= 0 {
		if n := count * ibs; n < len(data) {
			data = data[:n]
		}
	}
	full, part := len(data)/ibs, 0
	if len(data)%ibs != 0 {
		part = 1
	}
	if of == "" {
		c.out.Write(data)
	} else {
		target := c.s.abs(of)
		var prefix []byte
		if seek > 0 || conv["notrunc"] {
			prefix, _ = c.s.fs.ReadFile(target)
			if off := seek * obs; off > len(prefix) {
				prefix = append(prefix, make([]byte, off-len(prefix))...)
			} else if !conv["notrunc"] {
				prefix = prefix[:off]
			}
			if off := seek*obs + len(data); conv["notrunc"] && off < len(prefix) {
				data = append(data, prefix[off:]...)
			}
			if off := seek * obs; off <= len(prefix) {
				prefix = prefix[:off]
			}
		}
		if err := c.s.fs.WriteFile(target, append(prefix, data...), false); err != nil {
			c.errorf("dd: can't open '%s': %s\n", of, err.Error())
			return 1
		}
	}
	c.errorf("%d+%d records in\n%d+%d records out\n", full, part, full, part)
	return 0
}

func cmdOd(c *cctx) int {
	radix := byte('o')
	type fmtSpec struct {
		kind byte
		size int
	}
	var specs []fmtSpec
	skip, limit := 0, -1
	verbose := false
	var files []string
	args := c.args
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(prefix string) string {
			if len(a) > len(prefix) {
				return a[len(prefix):]
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case strings.HasPrefix(a, "-A"):
			if v := val("-A"); v != "" {
				radix = v[0]
			}
		case strings.HasPrefix(a, "-t"):
			v := val("-t")
			for j := 0; j < len(v); {
				k := v[j]
				j++
				size := 0
				for j < len(v) && v[j] >= '0' && v[j] <= '9' {
					size = size*10 + int(v[j]-'0')
					j++
				}
				if k == 'c' || k == 'a' {
					specs = append(specs, fmtSpec{'c', 1})
				} else if strings.IndexByte("xodu", k) >= 0 {
					if size == 0 {
						size = 4
					}
					specs = append(specs, fmtSpec{k, size})
				}
			}
		case strings.HasPrefix(a, "-N"):
			limit, _ = strconv.Atoi(val("-N"))
		case strings.HasPrefix(a, "-j"):
			skip, _ = strconv.Atoi(val("-j"))
		case a == "-v":
			verbose = true
		case a == "-c":
			specs = append(specs, fmtSpec{'c', 1})
		case a == "-x":
			specs = append(specs, fmtSpec{'x', 2})
		case a == "-b":
			specs = append(specs, fmtSpec{'o', 1})
		case a == "-d":
			specs = append(specs, fmtSpec{'u', 2})
		case a == "-o":
			specs = append(specs, fmtSpec{'o', 2})
		case a == "--":
		case len(a) > 1 && a[0] == '-':
		default:
			files = append(files, a)
		}
	}
	if len(specs) == 0 {
		specs = []fmtSpec{{'o', 2}}
	}
	data, rc := c.readInputs(files)
	if skip > len(data) {
		skip = len(data)
	}
	data = data[skip:]
	if limit >= 0 && limit < len(data) {
		data = data[:limit]
	}
	addr := func(n int) string {
		switch radix {
		case 'n':
			return ""
		case 'x':
			return fmt.Sprintf("%07x", n)
		case 'd':
			return fmt.Sprintf("%07d", n)
		}
		return fmt.Sprintf("%07o", n)
	}
	const width = 16
	var prev []byte
	star := false
	for off := 0; off < len(data); off += width {
		end := min(off+width, len(data))
		chunk := data[off:end]
		if !verbose && off > 0 && end-off == width && bytes.Equal(chunk, prev) {
			if !star {
				c.out.WriteString("*\n")
				star = true
			}
			continue
		}
		star = false
		prev = chunk
		for si, sp := range specs {
			var sb strings.Builder
			if sp.kind == 'c' {
				for _, b := range chunk {
					sb.WriteString(odChar(b))
				}
			} else {
				cw := map[byte]map[int]int{
					'x': {1: 2, 2: 4, 4: 8, 8: 16}, 'o': {1: 3, 2: 6, 4: 11, 8: 22},
					'd': {1: 4, 2: 6, 4: 11, 8: 20}, 'u': {1: 3, 2: 5, 4: 10, 8: 20},
				}[sp.kind][sp.size]
				if cw == 0 {
					cw = 8
				}
				for j := 0; j+sp.size <= len(chunk) || j < len(chunk); j += sp.size {
					var v uint64
					for k := sp.size - 1; k >= 0; k-- {
						v <<= 8
						if j+k < len(chunk) {
							v |= uint64(chunk[j+k])
						}
					}
					switch sp.kind {
					case 'x':
						sb.WriteString(fmt.Sprintf(" %0*x", cw, v))
					case 'o':
						sb.WriteString(fmt.Sprintf(" %0*o", cw, v))
					case 'u':
						sb.WriteString(fmt.Sprintf(" %*d", cw, v))
					default:
						sb.WriteString(fmt.Sprintf(" %*d", cw, signed(v, sp.size)))
					}
				}
			}
			prefix := addr(off)
			if si > 0 {
				prefix = strings.Repeat(" ", len(prefix))
			}
			c.out.WriteString(prefix + sb.String() + "\n")
		}
	}
	if a := addr(len(data)); a != "" {
		c.out.WriteString(a + "\n")
	}
	return rc
}

func signed(v uint64, size int) int64 {
	shift := uint(64 - 8*size)
	return int64(v<<shift) >> shift
}

func odChar(b byte) string {
	switch b {
	case 0:
		return "  \\0"
	case '\a':
		return "  \\a"
	case '\b':
		return "  \\b"
	case '\t':
		return "  \\t"
	case '\n':
		return "  \\n"
	case '\v':
		return "  \\v"
	case '\f':
		return "  \\f"
	case '\r':
		return "  \\r"
	}
	if b >= 0x20 && b < 0x7f {
		return "   " + string(rune(b))
	}
	return fmt.Sprintf(" %03o", b)
}

func cmdHexdump(c *cctx) int {
	canonical := false
	limit, skip := -1, 0
	var files []string
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		switch {
		case a == "-C":
			canonical = true
		case a == "-n" && i+1 < len(c.args):
			i++
			limit, _ = strconv.Atoi(c.args[i])
		case a == "-s" && i+1 < len(c.args):
			i++
			skip, _ = strconv.Atoi(c.args[i])
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			files = append(files, a)
		}
	}
	data, rc := c.readInputs(files)
	if skip > len(data) {
		skip = len(data)
	}
	data = data[skip:]
	if limit >= 0 && limit < len(data) {
		data = data[:limit]
	}
	if !canonical {

		for off := 0; off < len(data); off += 16 {
			end := min(off+16, len(data))
			var sb strings.Builder
			fmt.Fprintf(&sb, "%07x", off+skip)
			for j := off; j < end; j += 2 {
				v := uint16(data[j])
				if j+1 < end {
					v |= uint16(data[j+1]) << 8
				}
				fmt.Fprintf(&sb, " %04x", v)
			}
			c.out.WriteString(sb.String() + "\n")
		}
		fmt.Fprintf(c.out, "%07x\n", len(data)+skip)
		return rc
	}
	writeHex(c.out, data, skip, true)
	return rc
}

func writeHex(out *bytes.Buffer, data []byte, base int, canonical bool) {
	var prev []byte
	star := false
	for off := 0; off < len(data); off += 16 {
		end := min(off+16, len(data))
		chunk := data[off:end]
		if off > 0 && end-off == 16 && bytes.Equal(chunk, prev) {
			if !star {
				out.WriteString("*\n")
				star = true
			}
			continue
		}
		star = false
		prev = chunk
		fmt.Fprintf(out, "%08x ", off+base)
		for j := 0; j < 16; j++ {
			if j == 8 {
				out.WriteByte(' ')
			}
			if off+j < end {
				fmt.Fprintf(out, " %02x", data[off+j])
			} else {
				out.WriteString("   ")
			}
		}
		out.WriteString("  |")
		for _, b := range chunk {
			if b >= 0x20 && b < 0x7f {
				out.WriteByte(b)
			} else {
				out.WriteByte('.')
			}
		}
		out.WriteString("|\n")
	}
	fmt.Fprintf(out, "%08x\n", len(data)+base)
}

func cmdXxd(c *cctx) int {
	plain := false
	limit, skip := -1, 0
	var files []string
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		switch {
		case a == "-p" || a == "-ps" || a == "-plain":
			plain = true
		case a == "-l" && i+1 < len(c.args):
			i++
			limit, _ = strconv.Atoi(c.args[i])
		case a == "-s" && i+1 < len(c.args):
			i++
			skip, _ = strconv.Atoi(c.args[i])
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			files = append(files, a)
		}
	}
	data, rc := c.readInputs(files)
	if skip > len(data) {
		skip = len(data)
	}
	data = data[skip:]
	if limit >= 0 && limit < len(data) {
		data = data[:limit]
	}
	if plain {
		const per = 30
		for off := 0; off < len(data); off += per {
			end := min(off+per, len(data))
			fmt.Fprintf(c.out, "%x\n", data[off:end])
		}
		return rc
	}
	for off := 0; off < len(data); off += 16 {
		end := min(off+16, len(data))
		fmt.Fprintf(c.out, "%08x:", off+skip)
		for j := 0; j < 16; j += 2 {
			switch {
			case off+j+1 < end:
				fmt.Fprintf(c.out, " %02x%02x", data[off+j], data[off+j+1])
			case off+j < end:
				fmt.Fprintf(c.out, " %02x  ", data[off+j])
			default:
				c.out.WriteString("     ")
			}
		}
		c.out.WriteString("  ")
		for _, b := range data[off:end] {
			if b >= 0x20 && b < 0x7f {
				c.out.WriteByte(b)
			} else {
				c.out.WriteByte('.')
			}
		}
		c.out.WriteByte('\n')
	}
	return rc
}

func cmdStrings(c *cctx) int {
	minLen := 4
	var files []string
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		switch {
		case a == "-n" && i+1 < len(c.args):
			i++
			minLen, _ = strconv.Atoi(c.args[i])
		case strings.HasPrefix(a, "-n") && len(a) > 2:
			minLen, _ = strconv.Atoi(a[2:])
		case len(a) > 1 && a[0] == '-' && allDigits(a[1:]):
			minLen, _ = strconv.Atoi(a[1:])
		case strings.HasPrefix(a, "-") && len(a) > 1:
		default:
			files = append(files, a)
		}
	}
	if minLen < 1 {
		minLen = 4
	}
	data, rc := c.readInputs(files)
	var run []byte
	flush := func() {
		if len(run) >= minLen {
			c.out.Write(run)
			c.out.WriteByte('\n')
		}
		run = run[:0]
	}
	for _, b := range data {
		if b >= 0x20 && b < 0x7f || b == '\t' {
			run = append(run, b)
		} else {
			flush()
		}
	}
	flush()
	return rc
}

func cmdFile(c *cctx) int {
	_, rest := nonFlags(c.args)
	if len(rest) == 0 {
		c.errorf("Usage: file [OPTION...] [FILE...]\n")
		return 1
	}
	rc := 0
	for _, a := range rest {
		p := c.s.abs(a)
		info, ok := c.s.fs.Stat(p)
		switch {
		case !ok:
			c.printf("%s: cannot open `%s' (No such file or directory)\n", a, a)
			rc = 1
		case info.IsDir:
			c.printf("%s: directory\n", a)
		default:
			data, _ := c.s.fs.ReadFile(p)
			c.printf("%s: %s\n", a, describe(data))
		}
	}
	return rc
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

func describe(d []byte) string {
	switch {
	case len(d) == 0:
		return "empty"
	case len(d) >= 20 && bytes.HasPrefix(d, []byte("\x7fELF")):
		bits, order := "32-bit", "LSB"
		var rd func([]byte) uint16
		rd = func(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
		if d[4] == 2 {
			bits = "64-bit"
		}
		if d[5] == 2 {
			order = "MSB"
			rd = func(b []byte) uint16 { return uint16(b[1]) | uint16(b[0])<<8 }
		}
		kind := map[uint16]string{2: "executable", 3: "shared object"}[rd(d[16:])]
		if kind == "" {
			kind = "object"
		}
		mach := map[uint16]string{emX86: "Intel 80386", emMIPS: "MIPS, MIPS-I version 1 (SYSV)", emPPC: "PowerPC or cisco 4500",
			emARM: "ARM, EABI5 version 1 (SYSV)", emSH: "Renesas SH", emX86_64: "x86-64", emAArch64: "ARM aarch64"}[rd(d[18:])]
		if mach == "" {
			mach = "unknown arch"
		}
		return fmt.Sprintf("ELF %s %s %s, %s, statically linked, stripped", bits, order, kind, mach)
	case bytes.HasPrefix(d, []byte("#!/bin/sh")) || bytes.HasPrefix(d, []byte("#!/system/bin/sh")):
		return "POSIX shell script, ASCII text executable"
	case bytes.HasPrefix(d, []byte{0x1f, 0x8b}):
		return "gzip compressed data"
	case bytes.HasPrefix(d, []byte("PK\x03\x04")):
		return "Zip archive data"
	case bytes.HasPrefix(d, []byte("dex\n")):
		return "Dalvik dex file"
	}
	for _, b := range d {
		if b >= 0x80 || (b < 0x20 && b != '\n' && b != '\r' && b != '\t') {
			return "data"
		}
	}
	if bytes.Contains(d, []byte("\r\n")) {
		return "ASCII text, with CRLF line terminators"
	}
	if unicode.IsPrint(rune(d[0])) {
		return "ASCII text"
	}
	return "data"
}
