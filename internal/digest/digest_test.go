package digest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/generalregulator/botbait/internal/model"
)

var t0 = time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)

func writeEvents(t *testing.T, dir string, evs ...model.Event) {
	t.Helper()
	byDay := map[string][]byte{}
	for _, e := range evs {
		b, _ := json.Marshal(e)
		d := e.Timestamp.UTC().Format("2006-01-02")
		byDay[d] = append(append(byDay[d], b...), '\n')
	}
	for d, b := range byDay {
		if err := os.WriteFile(filepath.Join(dir, "events-"+d+".jsonl"), append(b, []byte("not json\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func ev(ip string, ago time.Duration, port int, proto string) model.Event {
	return model.Event{SrcIP: ip, Timestamp: t0.Add(-ago), DstPort: port, Protocol: proto}
}

func fixture(t *testing.T) string {
	dir := t.TempDir()
	geoA := model.Geo{Country: "Germany", CountryCode: "DE", ISP: "Acme <Net> & Co", ASN: "AS64496", Resolved: true}
	a := ev("203.0.113.1", time.Hour, 5555, "ADB")
	a.Geo = geoA
	a.Commands = []string{"uname   -a", "uname -a"}
	a.Techniques = []model.Technique{{ID: "T1059.004"}}
	a.Signature = "Hikvision CVE-2021-36260 (webLanguage injection)"
	a.Dropped = []model.DroppedFile{{Success: true, SHA256: strings.Repeat("a", 64), FileType: "ELF ARM", Size: 2048}}
	b := ev("203.0.113.1", 2*time.Hour, 5555, "ADB")
	b.Geo = geoA
	c := ev("203.0.113.2", 3*time.Hour, 7547, "HTTP")
	c.Downloads = []model.DownloadResult{{Success: true, SHA256: strings.Repeat("b", 64), FileType: "script", Size: 12}}
	old := ev("203.0.113.9", 8*24*time.Hour, 2323, "TELNET")
	writeEvents(t, dir, a, b, c, old)
	return dir
}

func TestCollectWindowAndAggregates(t *testing.T) {
	dir := fixture(t)
	d, err := Collect(dir, t0.Add(-Window), t0)
	if err != nil {
		t.Fatal(err)
	}
	if d.Sessions != 3 || len(d.IPSessions) != 2 {
		t.Fatalf("sessions=%d ips=%d", d.Sessions, len(d.IPSessions))
	}
	if d.Attacks != 1 {
		t.Errorf("attacks=%d", d.Attacks)
	}
	if d.Commands["uname -a"] != 2 {
		t.Errorf("command whitespace not normalised: %v", d.Commands)
	}
	if len(d.Samples) != 2 {
		t.Errorf("samples=%v", d.Samples)
	}
	if d.Services["5555/ADB"] != 2 {
		t.Errorf("services=%v", d.Services)
	}
}

func TestCollectMissingDirIsQuiet(t *testing.T) {
	d, err := Collect(t.TempDir(), t0.Add(-Window), t0)
	if err != nil || d.Sessions != 0 {
		t.Fatalf("%v %+v", err, d)
	}
	if got := d.Format(5); !strings.Contains(got, "No sessions") {
		t.Errorf("quiet day: %s", got)
	}
}

func TestEnrichResolvesBusiestFirstAndRespectsMax(t *testing.T) {
	dir := fixture(t)
	d, _ := Collect(dir, t0.Add(-Window), t0)
	var asked []string
	d.Enrich(context.Background(), func(_ context.Context, ip string) model.Geo {
		asked = append(asked, ip)
		return model.Geo{Country: "France", CountryCode: "FR", ASN: "AS64500", ISP: "X", Resolved: true}
	}, 5)
	if len(asked) != 1 || asked[0] != "203.0.113.2" {
		t.Fatalf("asked=%v", asked)
	}
	d2, _ := Collect(dir, t0.Add(-Window), t0)
	d2.Enrich(context.Background(), func(context.Context, string) model.Geo { t.Fatal("must not look up"); return model.Geo{} }, 0)
}

func TestFormatHTMLEscapingAndLimit(t *testing.T) {
	dir := fixture(t)
	d, _ := Collect(dir, t0.Add(-Window), t0)
	msg := d.Format(5)
	for _, want := range []string{"Acme &lt;Net&gt; &amp; Co", "🇩🇪", "• uname -a (×2)", "WEEKLY DIGEST", "<b>Top Commands:</b>", "<b>Source ASN:</b>", "• 5555/ADB (66.67%)", "🇩🇪 DE (100.00%)", "<b>Attack Type:</b>", "<b>Exploit Signatures:</b>", "• Hikvision CVE-2021-36260 (webLanguage inje", "• T1059.004 (33.33%)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}

	for i := 0; i < 400; i++ {
		d.Commands[strings.Repeat("x", 300)+string(rune('a'+i%26))+strings.Repeat("y", i)] = i + 1
	}
	big := d.Format(10)
	if strings.Contains(msg, strings.Repeat("a", 64)) || strings.Contains(msg, "New SHA") {
		t.Error("sample hashes must not appear in the digest")
	}
	if n := utf8.RuneCountInString(big); n > telegramLimit {
		t.Fatalf("message has %d chars", n)
	}
}

func TestSendDeliversWeeklyText(t *testing.T) {
	dir := fixture(t)
	o := &Options{Dir: dir, Top: 5, Now: func() time.Time { return t0 }}
	boom := errors.New("telegram down")
	if err := o.Send(context.Background(), func(context.Context, string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("err=%v", err)
	}
	var sent string
	if err := o.Send(context.Background(), func(_ context.Context, s string) error { sent = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sent, "WEEKLY DIGEST") || !strings.Contains(sent, "2026-02-23 → 2026-03-02 UTC") {
		t.Errorf("unexpected digest:\n%s", sent)
	}
	if _, err := os.Stat(filepath.Join(dir, "digest-state.json")); !os.IsNotExist(err) {
		t.Error("digest must not write any state file")
	}
}

func TestNextRunWeekly(t *testing.T) {

	mon := time.Date(2026, 3, 2, 8, 59, 0, 0, time.UTC)
	if got := NextRun(mon, time.Monday, "09:00"); !got.Equal(time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("same day before the time: %v", got)
	}
	if got := NextRun(mon.Add(time.Minute), time.Monday, "09:00"); !got.Equal(time.Date(2026, 3, 9, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("exactly at the time must schedule next week: %v", got)
	}
	if got := NextRun(mon, time.Sunday, "18:30"); !got.Equal(time.Date(2026, 3, 8, 18, 30, 0, 0, time.UTC)) {
		t.Errorf("sunday: %v", got)
	}
	if got := NextRun(mon, time.Friday, "garbage"); got.Hour() != 9 || got.Weekday() != time.Friday {
		t.Errorf("fallback: %v", got)
	}
}

func TestParseWeekday(t *testing.T) {
	for in, want := range map[string]time.Weekday{"mon": time.Monday, "Sunday": time.Sunday, " FRI ": time.Friday} {
		if got, ok := ParseWeekday(in); !ok || got != want {
			t.Errorf("%q -> %v %v", in, got, ok)
		}
	}
	if _, ok := ParseWeekday("tomorrow"); ok {
		t.Error("accepted garbage")
	}
}

func TestFlag(t *testing.T) {
	if flag("de") != "🇩🇪" || flag("") != "🏳️" || flag("1x") != "🏳️" {
		t.Error("flag mapping")
	}
}

func TestDigestCountsReportedAddresses(t *testing.T) {
	dir := t.TempDir()
	a := ev("203.0.113.1", time.Hour, 5555, "ADB")
	a.AbuseReported = true
	b := ev("203.0.113.1", 2*time.Hour, 5555, "ADB")
	b.AbuseReported = true
	c := ev("203.0.113.2", 3*time.Hour, 5555, "ADB")
	writeEvents(t, dir, a, b, c)
	d, err := Collect(dir, t0.Add(-Window), t0)
	if err != nil {
		t.Fatal(err)
	}
	if out := d.render(10); !strings.Contains(out, "Reported to AbuseIPDB: 1 IPs") {
		t.Fatalf("digest lacks the AbuseIPDB line:\n%s", out)
	}
	writeEvents(t, t.TempDir(), c)
	d2, _ := Collect(dir+"/none", t0.Add(-Window), t0)
	if strings.Contains(d2.render(10), "AbuseIPDB") {
		t.Fatal("the line must be absent when nothing was reported")
	}
}
