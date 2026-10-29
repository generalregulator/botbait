package ioc

import (
	"encoding/base64"
	"html"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/generalregulator/botbait/internal/model"
)

const (
	maxItems  = 20
	maxURLLen = 2048
)

var (
	urlRe = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>\\|;` + "`" + `(){}\[\]^]+`)

	bareFetchRe = regexp.MustCompile(`(?i)\b(?:wget|curl)\b[^\n;|&]*?\s((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/[^\s;|&'"<>` + "`" + `]+)`)

	ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	domainRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b`)

	nfsMountRe = regexp.MustCompile(`(?im)(?:^|[;&|(\x60$])\s*(?:(?:/usr)?/bin/|busybox\s+)?mount\b[^;\n|&]*?\s((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,24}):(/[^\s;|&)'"` + "`" + `]*)\s+([^\s;|&)'"` + "`" + `]+)`)

	hostHeaderRe = regexp.MustCompile(`(?im)^[ \t]*host[ \t]*:[^\n]*$`)

	dlToolRe = regexp.MustCompile(`(?i)\b(?:wget|curl|tftp|ftpget|lwp-download|fetch)\b`)
)

var FalsePositiveHosts = []string{
	"schemas.xmlsoap.org", "xmlsoap.org", "w3.org", "schemas.microsoft.com",
	"schemas.dmtf.org", "dslforum.org", "purl.org", "openxmlformats.org",
	"schemas.upnp.org", "upnp.org", "ietf.org", "xmlns.com", "oasis-open.org",
	"example.com", "example.org", "example.net", "localhost",
}

var knownTLDs = toSet("com", "net", "org", "info", "biz", "io", "co", "cc", "tk", "ml", "ga", "cf", "gq",
	"xyz", "top", "site", "online", "club", "work", "pw", "ws", "su", "ru", "cn", "ua", "by", "kz",
	"in", "br", "ir", "tr", "id", "vn", "th", "kr", "jp", "hk", "tw", "eu", "de", "fr", "nl", "uk",
	"it", "es", "pl", "ro", "bg", "cz", "us", "ca", "mx", "ar", "za", "ng", "ke", "me", "tv", "to",
	"link", "live", "shop", "store", "tech", "pro", "mobi", "bid", "win", "icu", "vip", "wang", "ltd")

var downloadExt = toSet(".sh", ".bin", ".elf", ".exe", ".dll", ".so", ".apk", ".jar", ".ps1", ".bat",
	".arm", ".arm4", ".arm5", ".arm6", ".arm7", ".arm8", ".aarch64", ".mips", ".mipsel", ".mpsl",
	".mps", ".x86", ".x86_64", ".x64", ".i386", ".i486", ".i586", ".i686", ".ppc", ".ppc440fp",
	".powerpc", ".sh4", ".m68k", ".spc", ".sparc", ".arc", ".m", ".dbg")

func toSet(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

func StripHostHeader(s string) string { return hostHeaderRe.ReplaceAllString(s, "") }

var base64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

var base64Keywords = []string{"wget", "curl", "http://", "https://", "ftp://", "/bin/sh", "/bin/bash", "tftp", "chmod", "busybox", "nc "}

func decodedBlobs(s string) []string {
	var out []string
	for _, tok := range base64BlobRe.FindAllString(s, 16) {
		if len(out) >= 4 {
			break
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(tok, "="))
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(tok, "="))
		}
		if err != nil || len(raw) < 12 || len(raw) > 4096 {
			continue
		}
		printable := 0
		for _, c := range raw {
			if c == '\n' || c == '\t' || c >= 0x20 && c < 0x7f {
				printable++
			}
		}
		if printable*100 < len(raw)*95 {
			continue
		}
		low := strings.ToLower(string(raw))
		for _, k := range base64Keywords {
			if strings.Contains(low, k) {
				out = append(out, string(raw))
				break
			}
		}
	}
	return out
}

func Normalize(s string) string {
	dec := s
	for i := 0; i < 2; i++ {
		next := lenientUnescape(dec)
		if next == dec {
			break
		}
		dec = next
	}
	dec = html.UnescapeString(dec)
	for _, b := range decodedBlobs(dec) {
		dec += "\n" + b
	}
	if dec == s {
		return s
	}
	return s + "\n" + dec
}

func lenientUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if h, ok := unhex(s[i+1]); ok {
				if l, ok := unhex(s[i+2]); ok {
					sb.WriteByte(h<<4 | l)
					i += 2
					continue
				}
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func Extract(text string) model.IOCs {
	var out model.IOCs
	seenURL := map[string]bool{}
	seenIP := map[string]bool{}
	seenDom := map[string]bool{}

	addURL := func(raw string, ctxDownload bool) {
		u, ok := cleanURL(raw)
		if !ok || len(out.URLs) >= maxItems && !seenURL[u.String()] {
			return
		}
		s := u.String()
		if !seenURL[s] {
			seenURL[s] = true
			out.URLs = append(out.URLs, s)
		}
		if (ctxDownload || looksLikeBinary(u)) && !contains(out.DownloadURLs, s) {
			out.DownloadURLs = append(out.DownloadURLs, s)
		}
		host := strings.ToLower(u.Hostname())
		if _, err := netip.ParseAddr(host); err != nil && !seenDom[host] && len(out.Domains) < maxItems {
			seenDom[host] = true
			out.Domains = append(out.Domains, host)
		}
	}

	for _, loc := range urlRe.FindAllStringIndex(text, -1) {
		addURL(text[loc[0]:loc[1]], inDownloadContext(text, loc[0]))
	}
	for _, m := range bareFetchRe.FindAllStringSubmatch(text, -1) {
		addURL("http://"+m[1], true)
	}

	for _, m := range nfsMountRe.FindAllStringSubmatch(text, -1) {
		if len(out.NFS) >= 5 {
			break
		}
		host := strings.ToLower(m[1])
		if ip, err := netip.ParseAddr(host); err == nil {
			if !isPublicIP(ip) {
				continue
			}
		} else if isFalsePositiveHost(host) {
			continue
		}
		entry := host + ":" + m[2]
		if script := mountedScript(text, m[3]); script != "" {
			entry += " → " + script
		}
		if !contains(out.NFS, entry) {
			out.NFS = append(out.NFS, entry)
		}
	}

	for _, m := range ipRe.FindAllString(text, -1) {
		ip, err := netip.ParseAddr(m)
		if err != nil || !isPublicIP(ip) || seenIP[m] || len(out.IPs) >= maxItems {
			continue
		}
		seenIP[m] = true
		out.IPs = append(out.IPs, m)
	}

	for _, m := range domainRe.FindAllStringSubmatch(text, -1) {
		d := strings.ToLower(m[0])
		if !knownTLDs[strings.ToLower(m[1])] || isFalsePositiveHost(d) || seenDom[d] || len(out.Domains) >= maxItems {
			continue
		}
		if _, err := netip.ParseAddr(d); err == nil {
			continue
		}
		seenDom[d] = true
		out.Domains = append(out.Domains, d)
	}
	return out
}

func mountedScript(text, mountPoint string) string {
	mp := strings.TrimSuffix(strings.TrimPrefix(mountPoint, "./"), "/")
	if mp == "" {
		return ""
	}
	re, err := regexp.Compile(`(?:^|[\s;|&(])(?:sh|bash|ash|source|\.)\s+(?:\./)?` + regexp.QuoteMeta(mp) + `/([^\s;|&)'"` + "`" + `]+)`)
	if err != nil {
		return ""
	}
	if m := re.FindStringSubmatch(text); m != nil {
		return m[1]
	}
	return ""
}

func cleanURL(raw string) (*url.URL, bool) {
	if i := strings.Index(raw, "&&"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.IndexByte(raw, '$'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimRight(raw, ".,:;!?)]}'\"")
	if raw == "" || len(raw) > maxURLLen {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, false
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if isFalsePositiveHost(u.Hostname()) {
		return nil, false
	}
	return u, true
}

func isFalsePositiveHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, bad := range FalsePositiveHosts {
		if h == bad || strings.HasSuffix(h, "."+bad) {
			return true
		}
	}
	return false
}

func isPublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func looksLikeBinary(u *url.URL) bool {
	return downloadExt[strings.ToLower(path.Ext(u.Path))]
}

func inDownloadContext(text string, idx int) bool {
	start := idx - 200
	if start < 0 {
		start = 0
	}
	seg := text[start:idx]
	for _, sep := range []string{"\n", ";", "&&", "||", "|", "`", "$("} {
		if i := strings.LastIndex(seg, sep); i >= 0 {
			seg = seg[i+len(sep):]
		}
	}
	return dlToolRe.MatchString(seg)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
