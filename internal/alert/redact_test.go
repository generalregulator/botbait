package alert

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/metrics"
	"github.com/generalregulator/botbait/internal/model"
	addrredact "github.com/generalregulator/botbait/internal/redact"
)

func dahuaEvent() *model.Event {
	return &model.Event{
		SrcIP: "78.40.194.232", DstPort: 80, Protocol: "HTTP", Action: "HTTP POST", Signature: "Dahua CVE-2021-33045 (loopback login bypass)",
		Payload:    "POST /RPC2_Login HTTP/1.1\nHost: 185.237.185.88:80\nContent-Type: application/json\n\n{\"method\":\"global.login\"}",
		Geo:        model.Geo{Country: "The Netherlands", ISP: "Servers Tech Fzco", ASN: "AS216071"},
		Techniques: []model.Technique{{ID: "T1190", Name: "Exploit Public-Facing Application"}},
	}
}

func TestFormatHidesOwnAddress(t *testing.T) {
	r := addrredact.New()
	r.Add("185.237.185.88")
	msg := FormatRedacted(dahuaEvent(), 1200, r)
	if strings.Contains(msg, "185.237.185.88") {
		t.Errorf("own address leaked:\n%s", msg)
	}
	if !strings.Contains(msg, "Host: [REDACTED]:80") {
		t.Errorf("host line not redacted:\n%s", msg)
	}
	if !strings.Contains(msg, "<code>78.40.194.232</code>") {
		t.Error("attacker address must stay visible")
	}
	if Format(dahuaEvent(), 1200) == msg || !strings.Contains(Format(dahuaEvent(), 1200), "185.237.185.88") {
		t.Error("Format without a redactor must be unchanged")
	}
}

func TestRedactionDoesNotMutateEventAndKeepsDownloadLookup(t *testing.T) {
	ev := sampleEvent()
	r := addrredact.New()
	r.Add("203.0.113.50")
	msg := FormatRedacted(ev, 1200, r)
	if strings.Contains(msg, "203.0.113.50") {
		t.Errorf("leak:\n%s", msg)
	}
	if !strings.Contains(msg, "SHA256: <code>ab12</code>") {
		t.Errorf("saved-sample line lost after redaction:\n%s", msg)
	}
	if !strings.Contains(ev.Payload, "203.0.113.50") || ev.IOCs.URLs[0] != "http://203.0.113.50/m.sh" || ev.Downloads[0].URL != "http://203.0.113.50/m.sh" {
		t.Error("the stored event was modified; logs must stay raw")
	}
}

func TestRedactionNeverHidesAttackerAddress(t *testing.T) {
	ev := dahuaEvent()
	r := addrredact.New()
	r.Add(ev.SrcIP)
	msg := FormatRedacted(ev, 1200, r)
	if !strings.Contains(msg, "<code>78.40.194.232</code>") {
		t.Errorf("attacker address redacted:\n%s", msg)
	}
}

func TestRedactedMessageStaysWithinTelegramLimit(t *testing.T) {
	ev := dahuaEvent()
	ev.Payload = strings.Repeat("Host: 1.1.1.1\n", 400)
	r := addrredact.New()
	r.Add("1.1.1.1")
	msg := FormatRedacted(ev, 3000, r)
	if runeLen(msg) > maxMessageRunes {
		t.Errorf("message has %d runes", runeLen(msg))
	}
}

func TestNotifierSendsRedactedText(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	r := addrredact.New()
	r.Add("185.237.185.88")
	n := NewNotifier("123:ABC", "42", srv.URL, 60, 10, time.Hour, 1200, &metrics.Metrics{}, WithRedactor(r))
	ok, err := n.Notify(context.Background(), dahuaEvent())
	if err != nil || !ok {
		t.Fatalf("notify: %v %v", ok, err)
	}
	if strings.Contains(body, "185.237.185.88") || !strings.Contains(body, "REDACTED") {
		t.Errorf("request body: %s", body)
	}
}
