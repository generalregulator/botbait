package alert

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/generalregulator/botbait/internal/model"
)

const (
	maxMessageRunes = 4000
	truncatedMarker = "...[TRUNCATED]"
	maxURLsShown    = 5
	maxURLRunes     = 200
)

func escHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

func Format(ev *model.Event, payloadMax int) string {
	payload := strings.ReplaceAll(strings.TrimSpace(firstNonEmpty(ev.Payload, ev.Text)), "\r", "")
	truncated := ev.Truncated || runeLen(payload) > payloadMax
	p := cutRunes(payload, payloadMax)
	urls := maxURLsShown

	for {
		msg := render(ev, p, truncated, urls)
		if runeLen(msg) <= maxMessageRunes {
			return msg
		}
		switch {
		case runeLen(p) > 0:
			p = cutRunes(p, runeLen(p)*3/4)
			truncated = true
		case urls > 1:
			urls--
		default:
			return cutRunes(msg, maxMessageRunes)
		}
	}
}

func render(ev *model.Event, payload string, truncated bool, maxURLs int) string {
	var b strings.Builder

	fmt.Fprintf(&b, "🚨\u00a0<b>HONEYPOT ALERT (%s)</b>\u00a0🚨\n", escHTML(ev.Service()))
	fmt.Fprintf(&b, "🌐 <b>Attacker IP:</b> <code>%s</code>\n", escHTML(ev.SrcIP))
	fmt.Fprintf(&b, "🏢 <b>ISP/ASN:</b> <code>%s</code>\n", escHTML(ispLine(ev.Geo)))
	fmt.Fprintf(&b, "🏷 <b>MITRE ATT&amp;CK:</b> <code>%s</code>\n\n", escHTML(techniqueLine(ev.Techniques)))

	b.WriteString("📦 Parsed Payload Data:\n")
	fmt.Fprintf(&b, "<pre>[%s]\n\n", escHTML(actionLabel(ev)))
	if payload == "" && !truncated {
		b.WriteString("(empty)")
	} else {
		b.WriteString(escHTML(payload))
		if truncated {
			b.WriteString(truncatedMarker)
		}
	}
	b.WriteString("</pre>\n\n")

	b.WriteString("🎯 Extracted IOCs &amp; Payloads:\n")
	writeIOCs(&b, ev, maxURLs)
	return strings.TrimRight(b.String(), "\n")
}

type Button struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

func Buttons(ev *model.Event) [][]Button {
	ip := url.PathEscape(ev.SrcIP)
	return [][]Button{
		{
			{Text: "🔬 VirusTotal", URL: "https://www.virustotal.com/gui/ip-address/" + ip},
			{Text: "🛡 AbuseIPDB", URL: "https://www.abuseipdb.com/check/" + ip},
		},
		{
			{Text: "🌐 Check-Host", URL: "https://check-host.net/ip-info?host=" + url.QueryEscape(ev.SrcIP)},
		},
	}
}

func writeIOCs(b *strings.Builder, ev *model.Event, maxURLs int) {
	results := make(map[string]model.DownloadResult, len(ev.Downloads))
	for _, d := range ev.Downloads {
		results[d.URL] = d
	}
	isDL := make(map[string]bool, len(ev.IOCs.DownloadURLs))
	for _, u := range ev.IOCs.DownloadURLs {
		isDL[u] = true
	}

	ordered := append([]string{}, ev.IOCs.DownloadURLs...)
	for _, u := range ev.IOCs.URLs {
		if !isDL[u] {
			ordered = append(ordered, u)
		}
	}

	for _, x := range ev.IOCs.NFS {
		fmt.Fprintf(b, "📂 NFS: %s\n", escHTML(cutRunes(x, maxURLRunes)))
	}
	nfsHosts := make(map[string]bool, len(ev.IOCs.NFS))
	for _, x := range ev.IOCs.NFS {
		host, _, _ := strings.Cut(x, ":")
		nfsHosts[host] = true
	}

	shown := 0
	for _, u := range ordered {
		if shown >= maxURLs {
			break
		}
		fmt.Fprintf(b, "🔗 %s\n", escHTML(cutRunes(u, maxURLRunes)))
		if isDL[u] {
			writeSaved(b, results, u)
		}
		shown++
	}
	if len(ordered) > shown {
		fmt.Fprintf(b, "… +%d more\n", len(ordered)-shown)
	}
	if len(ordered) == 0 {

		var extra []string
		for _, x := range append(append([]string{}, ev.IOCs.IPs...), ev.IOCs.Domains...) {
			if !nfsHosts[x] {
				extra = append(extra, x)
			}
		}
		for i, x := range extra {
			if i >= maxURLs {
				fmt.Fprintf(b, "… +%d more\n", len(extra)-i)
				break
			}
			fmt.Fprintf(b, "🔗 %s\n", escHTML(cutRunes(x, maxURLRunes)))
		}
		if len(extra) == 0 && len(ev.Dropped) == 0 && len(ev.IOCs.NFS) == 0 {
			b.WriteString("🔗 None\n")
		}
	}
	writeDropped(b, ev)
}

func writeDropped(b *strings.Builder, ev *model.Event) {
	const maxShown = 3
	for i, d := range ev.Dropped {
		if i >= maxShown {
			fmt.Fprintf(b, "… +%d more files\n", len(ev.Dropped)-maxShown)
			break
		}
		fmt.Fprintf(b, "📎 Dropped: %s (%s)\n", escHTML(cutRunes(d.Path, maxURLRunes)), escHTML(d.Via))
		if d.Success {

			fmt.Fprintf(b, "📦 SHA256: <code>%s</code> | %d B (%s)\n",
				escHTML(d.SHA256), d.Size, escHTML(d.FileType))
		} else {
			fmt.Fprintf(b, "📦 Saved: %s\n", escHTML(d.Status))
		}
	}
}

func writeSaved(b *strings.Builder, results map[string]model.DownloadResult, u string) {
	r, ok := results[u]
	switch {
	case !ok:
		b.WriteString("📦 Saved: Not attempted\n")
	case r.Success:
		fmt.Fprintf(b, "📦 SHA256: <code>%s</code> | %d B (%s)\n", escHTML(r.SHA256), r.Size, escHTML(r.FileType))
	default:
		fmt.Fprintf(b, "📦 Saved: %s\n", escHTML(r.Status))
	}
}

func ispLine(g model.Geo) string {
	return strings.TrimSpace(fmt.Sprintf("%s - %s %s", g.Country, g.ISP, g.ASN))
}

func techniqueLine(ts []model.Technique) string {
	if len(ts) == 0 {
		return "None"
	}
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.String()
	}
	return strings.Join(parts, ", ")
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func actionLabel(ev *model.Event) string {
	if ev.Signature == "" {
		return ev.Action
	}
	return ev.Action + " | " + ev.Signature
}
