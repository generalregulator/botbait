package digest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/generalregulator/botbait/internal/model"
)

const telegramLimit = 4096

type Data struct {
	From, To time.Time

	Sessions int
	Attacks  int

	IPSessions map[string]int
	IPGeo      map[string]model.Geo
	Services   map[string]int
	Techniques map[string]int
	Signatures map[string]int
	AbuseIPs   map[string]struct{}
	Commands   map[string]int
	Samples    map[string]struct{}
}

func newData(from, to time.Time) *Data {
	return &Data{
		From: from, To: to,
		IPSessions: map[string]int{}, IPGeo: map[string]model.Geo{},
		Services: map[string]int{}, Techniques: map[string]int{}, Signatures: map[string]int{}, AbuseIPs: map[string]struct{}{}, Commands: map[string]int{}, Samples: map[string]struct{}{},
	}
}

var attackTechniques = map[string]bool{"T1190": true, "T1059.004": true, "T1105": true, "T1496": true}

const Window = 7 * 24 * time.Hour

func Collect(dir string, from, to time.Time) (*Data, error) {
	d := newData(from, to)
	for day := from.UTC().Truncate(24 * time.Hour); day.Before(to); day = day.Add(24 * time.Hour) {
		name := filepath.Join(dir, "events-"+day.Format("2006-01-02")+".jsonl")
		f, err := os.Open(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		err = d.read(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return d, nil
}

func (d *Data) read(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var ev model.Event
			if json.Unmarshal(line, &ev) == nil {
				d.add(&ev)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (d *Data) add(ev *model.Event) {
	if ev.Timestamp.Before(d.From) || !ev.Timestamp.Before(d.To) {
		return
	}
	d.Sessions++
	d.IPSessions[ev.SrcIP]++
	d.Services[ev.Service()]++
	if ev.Geo.Resolved {
		d.IPGeo[ev.SrcIP] = ev.Geo
	}
	if ev.Signature != "" {
		d.Signatures[ev.Signature]++
	}
	if ev.AbuseReported {
		d.AbuseIPs[ev.SrcIP] = struct{}{}
	}
	seenTech := map[string]bool{}
	for _, t := range ev.Techniques {
		if k := strings.TrimSpace(t.ID + " " + t.Name); !seenTech[k] {
			seenTech[k] = true
			d.Techniques[k]++
		}
	}
	for _, t := range ev.Techniques {
		if attackTechniques[t.ID] {
			d.Attacks++
			break
		}
	}
	for _, c := range ev.Commands {
		if c = normaliseCommand(c); c != "" {
			d.Commands[c]++
		}
	}
	for _, r := range ev.Downloads {
		if r.Success && r.SHA256 != "" {
			d.Samples[r.SHA256] = struct{}{}
		}
	}
	for _, f := range ev.Dropped {
		if f.Success && f.SHA256 != "" {
			d.Samples[f.SHA256] = struct{}{}
		}
	}
}

func normaliseCommand(c string) string {
	return strings.Join(strings.Fields(c), " ")
}

type Resolver func(ctx context.Context, ip string) model.Geo

func (d *Data) Enrich(ctx context.Context, lookup Resolver, max int) {
	if lookup == nil || max <= 0 {
		return
	}
	type ipc struct {
		ip string
		n  int
	}
	var todo []ipc
	for ip, n := range d.IPSessions {
		if _, ok := d.IPGeo[ip]; !ok {
			todo = append(todo, ipc{ip, n})
		}
	}
	sort.Slice(todo, func(i, j int) bool {
		if todo[i].n != todo[j].n {
			return todo[i].n > todo[j].n
		}
		return todo[i].ip < todo[j].ip
	})
	for i, t := range todo {
		if i >= max || ctx.Err() != nil {
			return
		}
		if g := lookup(ctx, t.ip); g.Resolved {
			d.IPGeo[t.ip] = g
		}
	}
}

func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func num(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func flag(cc string) string {
	cc = strings.ToUpper(cc)
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return "🏳️"
	}
	return string([]rune{0x1F1E6 + rune(cc[0]-'A'), 0x1F1E6 + rune(cc[1]-'A')})
}

type rank struct {
	key, label, cc string
	sessions       int
	ips            map[string]bool
}

func (d *Data) rankBy(key func(model.Geo) (k, label, cc string)) []*rank {
	m := map[string]*rank{}
	for ip, g := range d.IPGeo {
		k, label, cc := key(g)
		if k == "" {
			continue
		}
		r := m[k]
		if r == nil {
			r = &rank{key: k, label: label, cc: cc, ips: map[string]bool{}}
			m[k] = r
		}
		r.sessions += d.IPSessions[ip]
		r.ips[ip] = true
	}
	out := make([]*rank, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].sessions != out[j].sessions {
			return out[i].sessions > out[j].sessions
		}
		return out[i].key < out[j].key
	})
	return out
}

func (d *Data) Format(top int) string {
	for {
		msg := d.render(top)
		if utf8.RuneCountInString(msg) <= telegramLimit || top <= 1 {
			if utf8.RuneCountInString(msg) > telegramLimit {
				msg = string([]rune(msg)[:telegramLimit-1]) + "…"
			}
			return msg
		}
		top--
	}
}

func padRight(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}

func padLeft(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return strings.Repeat(" ", n-k) + s
	}
	return s
}

type kv struct {
	k string
	n int
}

func sorted(m map[string]int) []kv {
	out := make([]kv, 0, len(m))
	for k, n := range m {
		out = append(out, kv{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	return out
}

func block(b *strings.Builder, heading string, lines []string) {
	fmt.Fprintf(b, "\n%s\n<pre>%s</pre>\n", heading, strings.Join(lines, "\n"))
}

func pct(n, total int) string {
	if total <= 0 {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(n)/float64(total))
}

func (d *Data) render(top int) string {
	var b strings.Builder
	b.WriteString("🎲\u00a0<b>HONEYPOT WEEKLY DIGEST</b>\u00a0🎲\n")
	fmt.Fprintf(&b, "🗓 <code>%s → %s UTC</code>\n", d.From.UTC().Format("2006-01-02"), d.To.UTC().Format("2006-01-02"))

	stats := []string{
		"• Sessions: " + num(d.Sessions),
		"• Unique IPs: " + num(len(d.IPSessions)),
		"• Attacks: " + num(d.Attacks),
		"• Samples captured: " + num(len(d.Samples)),
	}
	if len(d.AbuseIPs) > 0 {
		stats = append(stats, "• Reported to AbuseIPDB: "+num(len(d.AbuseIPs))+" IPs")
	}
	block(&b, "📈 <b>Metric Statistics:</b>", stats)
	if d.Sessions == 0 {
		b.WriteString("\nNo sessions in this period.")
		return b.String()
	}

	var lines []string
	share := func(m map[string]int, n int, cutAt int) []string {
		out := []string{}
		for i, e := range sorted(m) {
			if i >= n {
				break
			}
			out = append(out, fmt.Sprintf("• %s (%s)", esc(cut(e.k, cutAt)), pct(e.n, d.Sessions)))
		}
		return out
	}

	if lines = share(d.Techniques, top, 30); len(lines) > 0 {
		block(&b, "🚨 <b>Attack Type:</b>", lines)
	}
	if lines = share(d.Signatures, top, 44); len(lines) > 0 {
		block(&b, "🎯 <b>Exploit Signatures:</b>", lines)
	}
	if lines = share(d.Services, top, 34); len(lines) > 0 {
		block(&b, "🚪 <b>Target Port:</b>", lines)
	}

	resolved := 0
	for ip := range d.IPGeo {
		resolved += d.IPSessions[ip]
	}
	asns := d.rankBy(func(g model.Geo) (string, string, string) {
		if g.ASN == "" {
			return "", "", ""
		}
		return g.ASN, firstNonEmpty(g.ISP, g.ASName), ""
	})
	if len(asns) > 0 {
		lines = lines[:0]
		for i, r := range asns {
			if i >= top {
				break
			}
			name := esc(r.key)
			if r.label != "" {
				name += " - " + esc(cut(r.label, 24))
			}
			lines = append(lines, fmt.Sprintf("• %s (%s)", name, pct(r.sessions, resolved)))
		}
		block(&b, "🏢 <b>Source ASN:</b>", lines)
	}

	countries := d.rankBy(func(g model.Geo) (string, string, string) {
		if g.Country == "" || g.Country == "Unknown" {
			return "", "", ""
		}
		return g.Country, g.Country, g.CountryCode
	})
	if len(countries) > 0 {
		lines = lines[:0]
		for i, r := range countries {
			if i >= top {
				break
			}
			label := strings.ToUpper(r.cc)
			if label == "" {
				label = cut(r.label, 18)
			}
			lines = append(lines, fmt.Sprintf("• %s %s (%s)", flag(r.cc), esc(label), pct(r.sessions, resolved)))
		}
		block(&b, "🌍 <b>Attack Source Countries:</b>", lines)
	}
	if len(d.IPGeo) < len(d.IPSessions) {
		fmt.Fprintf(&b, "<i>ASN/country known for %s of %s IPs</i>\n", num(len(d.IPGeo)), num(len(d.IPSessions)))
	}

	if cmds := sorted(d.Commands); len(cmds) > 0 {
		lines = lines[:0]
		for i, c := range cmds {
			if i >= top {
				break
			}
			lines = append(lines, fmt.Sprintf("• %s (×%s)", esc(cut(c.k, 30)), num(c.n)))
		}
		block(&b, "⌨️ <b>Top Commands:</b>", lines)
	}
	return strings.TrimRight(b.String(), "\n")
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
