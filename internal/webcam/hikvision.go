package webcam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"regexp"
	"strings"
)

const hikLogin = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Network Camera</title></head>
<body style="font-family:sans-serif;background:#f2f2f2"><div style="width:320px;margin:120px auto;padding:24px;background:#fff;border:1px solid #ccc">
<h3>Network Camera</h3><form method="post" action="/doc/page/login.asp"><p><input name="username" placeholder="User Name"></p>
<p><input name="password" type="password" placeholder="Password"></p><p><button type="submit">Login</button></p></form></div></body></html>`

const hikBypassToken = "YWRtaW46MTEK"

const hikRedirect = `<html><head><meta http-equiv="refresh" content="0; url=/doc/page/login.asp"></head><body></body></html>`

const hikStatusOK = `<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<requestURL>%s</requestURL><statusCode>1</statusCode><statusString>OK</statusString><subStatusCode>ok</subStatusCode>
</ResponseStatus>`

func (c *ctx) hikvision() {
	server := serverHeader(Hikvision)
	id := c.s.id
	model := id.Model[Hikvision]

	switch {
	case c.path == "/" || c.path == "/index.html":
		c.html(200, server, hikRedirect)
		return
	case c.path == "/doc/page/login.asp":
		c.html(200, server, hikLogin)
		return
	case c.path == "/sdk/weblanguage":
		c.webLanguage(server)
		return
	case c.path == "/bic/ssoservice/v1/applyct":
		c.applyCT(server)
		return
	}

	bypass := strings.TrimSpace(c.query.Get("auth")) == hikBypassToken
	allowed := c.authed || bypass
	known := c.hikvisionResource(server, allowed)
	if !known {
		if strings.HasPrefix(c.path, "/isapi/") || strings.HasPrefix(c.path, "/sdk/") {
			c.digest(server, model)
		}
		return
	}
	if bypass && c.r.Method == "GET" && c.resp.Status == 200 {
		c.resp.Signature = "Hikvision CVE-2017-7921 (auth parameter bypass)"
	}
}

func (c *ctx) hikvisionResource(server string, allowed bool) bool {
	id := c.s.id
	model := id.Model[Hikvision]
	p := strings.TrimPrefix(c.path, "/isapi")
	switch {
	case p == "/system/deviceinfo":
		if !allowed {
			c.digest(server, model)
			return true
		}
		c.set(200, "application/xml", []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<deviceName>IP CAMERA</deviceName><deviceID>%s</deviceID><model>%s</model><serialNumber>%s</serialNumber>
<macAddress>%s</macAddress><firmwareVersion>V5.4.0</firmwareVersion><firmwareReleasedDate>build 160401</firmwareReleasedDate>
<encoderVersion>V7.3</encoderVersion><deviceType>IPCamera</deviceType></DeviceInfo>`,
			id.token("devid", 8)+"-"+id.token("devid2", 4)+"-"+id.token("devid3", 12), model, id.Serial[Hikvision], id.MAC[Hikvision])), server)
		return true
	case p == "/security/users", strings.HasPrefix(p, "/security/users/"):
		if !allowed {
			c.digest(server, model)
			return true
		}
		c.set(200, "application/xml", []byte(`<?xml version="1.0" encoding="UTF-8"?>
<UserList version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema"><User><id>1</id><userName>admin</userName><userLevel>Administrator</userLevel></User></UserList>`), server)
		return true
	case p == "/system/configurationfile":
		if !allowed {
			c.digest(server, model)
			return true
		}
		c.set(200, "application/binary", c.filler(8192), server)
		c.resp.Extra = append(c.resp.Extra, [2]string{"Content-Disposition", `attachment; filename="configurationFile"`})
		return true
	case c.path == "/onvif-http/snapshot", strings.HasPrefix(p, "/streaming/channels/"):
		if !allowed {
			c.digest(server, model)
			return true
		}
		c.set(200, "image/jpeg", snapshot(), server)
		return true
	}
	return false
}

func (c *ctx) webLanguage(server string) {
	body := string(c.r.Body)
	if m := langRe.FindStringSubmatch(body); m != nil && c.r.Method == "PUT" {
		cmds := extractCommands(m[1])
		if len(cmds) > 0 || strings.Contains(m[1], "$(") || strings.ContainsAny(m[1], "`;|") {
			c.resp.Signature = "Hikvision CVE-2021-36260 (webLanguage injection)"
			c.resp.Commands = cmds
		}
	}
	c.set(200, "application/xml", []byte(fmt.Sprintf(hikStatusOK, "/SDK/webLanguage")), server)
}

var jndiRe = regexp.MustCompile(`(?i)^\s*(ldaps?|rmi|iiop|dns)://[^\s]{3,512}$`)

func (c *ctx) applyCT(server string) {
	if c.r.Method == "POST" && fastjsonExploit(c.r.Body) {
		c.resp.Signature = "Hikvision CVE-2025-34067 (applyCT fastjson deserialization)"
	}
	c.set(200, "application/json;charset=UTF-8", []byte(`{"code":"200","msg":"success","data":null}`), server)
}

func fastjsonExploit(body []byte) bool {
	if len(body) == 0 || len(body) > 64<<10 {
		return false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return false
	}
	typed, jndi := false, false
	var walk func(n any, depth int)
	walk = func(n any, depth int) {
		if depth > 16 {
			return
		}
		switch t := n.(type) {
		case map[string]any:
			for k, e := range t {
				if k == "@type" {
					typed = true
				}
				walk(e, depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		case string:
			if jndiRe.MatchString(t) {
				jndi = true
			}
		}
	}
	walk(v, 0)
	return typed && jndi
}

func (c *ctx) filler(n int) []byte {
	out := make([]byte, 0, n)
	for i := 0; len(out) < n; i++ {
		out = append(out, []byte(c.s.id.token(fmt.Sprintf("cfg%d", i), 64))...)
	}
	return out[:n]
}

var snapshotJPEG = func() []byte {
	img := image.NewGray(image.Rect(0, 0, 64, 48))
	for y := 0; y < 48; y++ {
		for x := 0; x < 64; x++ {
			img.SetGray(x, y, color.Gray{Y: uint8(40 + (x*y)%60)})
		}
	}
	var b bytes.Buffer
	_ = jpeg.Encode(&b, img, &jpeg.Options{Quality: 60})
	return b.Bytes()
}()

func snapshot() []byte { return snapshotJPEG }
