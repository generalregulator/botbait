package webcam

const tvtLogin = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>NVMS-9000</title></head>
<body style="font-family:sans-serif;background:#e9edf2"><div style="width:320px;margin:120px auto;padding:24px;background:#fff;border:1px solid #bbb">
<h3>NVMS-9000</h3><form method="post" action="/"><p><input name="username" placeholder="User Name"></p>
<p><input name="password" type="password" placeholder="Password"></p><p><button type="submit">Login</button></p></form></div></body></html>`

func (c *ctx) tvt() {
	server := serverHeader(TVT)
	switch c.path {
	case "/", "/index.html", "/login.html":
		c.html(200, server, tvtLogin)
	}
}
