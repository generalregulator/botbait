package webcam

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const dahuaLogin = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>WEB SERVICE</title></head>
<body style="font-family:sans-serif;background:#1d2733;color:#fff"><div style="width:320px;margin:120px auto;padding:24px;background:#2b3a4a">
<h3>WEB SERVICE</h3><p><input id="user" placeholder="Username"></p><p><input id="password" type="password" placeholder="Password"></p>
<p><button>Login</button></p></div></body></html>`

type rpcRequest struct {
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  map[string]any  `json:"params"`
	Session json.RawMessage `json:"session"`
	id      int64
}

func (c *ctx) dahua() {
	server := serverHeader(Dahua)
	id := c.s.id
	realm := "Login to " + id.Serial[Dahua]

	switch {
	case c.path == "/" || c.path == "/index.html" || c.path == "/login.html":
		c.html(200, server, dahuaLogin)
		return
	case c.path == "/rpc2_login" && c.r.Method == "POST":
		c.rpcLogin(server, realm)
		return
	case c.path == "/rpc2" && c.r.Method == "POST":
		c.rpc(server)
		return
	case strings.HasPrefix(c.path, "/cgi-bin/"):
		c.dahuaCGI(server, realm)
		return
	}
}

func (c *ctx) parseRPC() (rpcRequest, bool) {
	var req rpcRequest
	if err := json.Unmarshal(c.r.Body, &req); err != nil {
		return req, false
	}
	req.id = 1
	if f, ok := req.ID.(float64); ok && f >= 0 && f < 1<<31 {
		req.id = int64(f)
	}
	return req, true
}

func (c *ctx) rpcLogin(server, realm string) {
	req, ok := c.parseRPC()
	if !ok {
		c.set(400, "application/json", []byte(`{"error":{"code":268894210,"message":"Bad request"},"result":false}`), server)
		return
	}
	session := c.s.id.token("session|"+strconv.FormatInt(req.id, 10), 32)

	client, _ := req.Params["clientType"].(string)
	addr, _ := req.Params["ipAddr"].(string)
	if strings.EqualFold(req.Method, "global.login") {
		switch {
		case strings.EqualFold(client, "NetKeyboard"):
			c.resp.Signature = "Dahua CVE-2021-33044 (NetKeyboard login bypass)"
		case strings.EqualFold(client, "Loopback") || strings.TrimSpace(addr) == "127.0.0.1":
			c.resp.Signature = "Dahua CVE-2021-33045 (loopback login bypass)"
		}
	}

	user, _ := req.Params["userName"].(string)
	pass, _ := req.Params["password"].(string)
	if c.resp.Signature == "" && pass == "" {
		body := fmt.Sprintf(`{"error":{"code":268632079,"message":"Component error: login challenge!"},"id":%d,"params":{"encryption":"Default","random":"%s","realm":"%s"},"result":false,"session":"%s"}`,
			req.id, c.s.id.token("random|"+strconv.FormatInt(req.id, 10), 10), realm, session)
		c.set(200, "application/json", []byte(body), server)
		return
	}
	if user != "" {
		c.creds = append(c.creds, Credential{clip(user, 64), clip(pass, 64)})
	}
	c.set(200, "application/json", []byte(fmt.Sprintf(`{"id":%d,"params":null,"result":true,"session":"%s"}`, req.id, session)), server)
}

func (c *ctx) rpc(server string) {
	req, ok := c.parseRPC()
	if !ok {
		c.set(400, "application/json", []byte(`{"error":{"code":268894210,"message":"Bad request"},"result":false}`), server)
		return
	}
	id := c.s.id
	var params string
	switch strings.ToLower(req.Method) {
	case "magicbox.getsysteminfo":
		params = fmt.Sprintf(`{"serialNumber":"%s","deviceType":"%s"}`, id.Serial[Dahua], id.Model[Dahua])
	case "magicbox.getdevicetype":
		params = fmt.Sprintf(`{"type":"%s"}`, id.Model[Dahua])
	default:
		params = "{}"
	}
	c.set(200, "application/json", []byte(fmt.Sprintf(`{"id":%d,"params":%s,"result":true,"session":%s}`, req.id, params, sessionOrNull(req.Session))), server)
}

func sessionOrNull(raw json.RawMessage) string {
	if len(raw) == 0 || len(raw) > 128 {
		return "null"
	}
	var s any
	if json.Unmarshal(raw, &s) != nil {
		return "null"
	}
	return string(raw)
}

func (c *ctx) dahuaCGI(server, realm string) {
	if !c.authed {
		c.digest(server, realm)
		return
	}
	id := c.s.id
	action := strings.ToLower(c.query.Get("action"))
	var body string
	switch {
	case strings.HasPrefix(c.path, "/cgi-bin/magicbox.cgi") && action == "getsysteminfo":
		body = fmt.Sprintf("serialNumber=%s\ndeviceType=%s\n", id.Serial[Dahua], id.Model[Dahua])
	case strings.HasPrefix(c.path, "/cgi-bin/magicbox.cgi") && action == "getdevicetype":
		body = fmt.Sprintf("type=%s\n", id.Model[Dahua])
	case strings.HasPrefix(c.path, "/cgi-bin/magicbox.cgi") && action == "getsoftwareversion":
		body = "version=2.800.0000000.4.R, Build Date: 2019-12-09\n"
	case strings.HasPrefix(c.path, "/cgi-bin/usermanager.cgi"):
		body = "users[0].Name=admin\nusers[0].Group=admin\n"
	default:
		body = "OK\n"
	}
	c.set(200, "text/plain", []byte(body), server)
}
