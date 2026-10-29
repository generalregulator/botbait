package mitre

import (
	"regexp"
	"sort"
	"strings"

	"github.com/generalregulator/botbait/internal/model"
)

var (
	T1190    = model.Technique{ID: "T1190", Name: "Exploit Public-Facing Application"}
	T1059004 = model.Technique{ID: "T1059.004", Name: "Unix Shell"}
	T1105    = model.Technique{ID: "T1105", Name: "Ingress Tool Transfer"}
	T1110001 = model.Technique{ID: "T1110.001", Name: "Password Guessing"}
	T1082    = model.Technique{ID: "T1082", Name: "System Information Discovery"}
	T1496    = model.Technique{ID: "T1496", Name: "Resource Hijacking"}
)

type Signals struct {
	Protocol     string
	Path         string
	Text         string
	Credentials  int
	DownloadURLs int
	Signature    string
	Strict       bool
	Dropped      int
}

var (
	soapRe = regexp.MustCompile(`(?i)(<\s*soap[-:\w]*:?envelope|soapenv:|urn:dslforum-org|newntpserver|setntpservers|soapaction:|<\s*u:\w+\s+xmlns:u=)`)

	injectionRe = regexp.MustCompile("(?i)(\\$\\([^)]{0,200}\\)|`[^`]{1,200}`|[;&|]\\s*(wget|curl|sh|bash|cd|rm|busybox|chmod|nc|tftp)(\\s|\\+|\\$\\{ifs\\}|$)|\\|\\s*(ba)?sh\\b|\\$\\{ifs\\}|\\(\\)\\s*\\{\\s*:;\\s*\\}|\\$\\{jndi:)")

	webExploitRe = regexp.MustCompile(`(?i)(allow_url_include|auto_prepend_file|auto_append_file|php://(input|filter)|<\?php[^?]{0,600}\b(shell_exec|system|passthru|exec|popen|proc_open|eval|assert)\s*\()`)

	traversalRe = regexp.MustCompile(`(?i)(\.\./\.\./|/etc/(passwd|shadow)|\.\.%2f|/proc/self/)`)

	shellRe = regexp.MustCompile(`(?i)(` +
		`\bcd\s+/(tmp|var|data|dev|mnt|run|home|sdcard)\b|` +
		`\brm\s+-[a-z]*[rf][a-z]*\b|` +
		`\b(wget|curl)\s+[-\w:/."']|` +
		`\bchmod\s+(\+x|[0-7]{3,4})\b|` +
		`\bbusybox\b|` +
		`/bin/(ba)?sh\b|\bsh\s+-c\b|` +
		`\|\s*(ba)?sh\b|\b(ba)?sh\s+/(tmp|var|data|dev)/|` +
		`\btftp\b[^\n;]*\s-[gr]\b|\bftpget\b|` +
		`\b(shell_exec|passthru|proc_open|popen)\s*\(|` +
		`\bnohup\b|\bkillall\b|\bpkill\b|` +
		`\becho\s+-e\s+["']?\\x)`)

	transferRe = regexp.MustCompile(`(?i)(\btftp\b[^\n;]*\s-[gr]\b|\bftpget\b|\bbusybox\s+(wget|tftp|ftpget)\b)`)

	discoveryRe = regexp.MustCompile(`(?i)(\buname\b|/proc/(cpuinfo|version|meminfo|mounts)\b|\bgetprop\b|\bbuild\.prop\b|\bpm\s+list\s+packages\b|\blscpu\b|/etc/(os-release|issue)\b)`)

	minerRe = regexp.MustCompile(`(?i)(xmrig|minerd|cpuminer|stratum\+(tcp|ssl)|--donate-level|cryptonight|minexmr|supportxmr|nanopool|\bmonero\b)`)
)

var exploitPaths = []string{
	"/cgi-bin/", "/boaform/", "/gponform/", "/hnap1", "/setup.cgi", "/tmunblock.cgi",
	"/ctrlt/", "/upnp/control", "/picsdesc.xml", "/ud/act", "/vendor/phpunit",
	"/.env", "/shell?", "/command.php", "/apply.cgi", "/actuator", "/goform/",
	"/wls-wsat/", "/invoker/", "/manager/html", "/wp-content/plugins/",
}

func Classify(s Signals) []model.Technique {
	text := s.Text
	set := map[string]model.Technique{}
	add := func(t model.Technique) { set[t.ID] = t }

	if s.Signature != "" || s.Protocol == "HTTP" && isWebExploit(s.Path, text, s.Strict) {
		add(T1190)
	}
	if shellRe.MatchString(text) {
		add(T1059004)
	}
	if s.DownloadURLs > 0 || s.Dropped > 0 || transferRe.MatchString(text) {
		add(T1105)
	}
	if s.Credentials >= 2 {
		add(T1110001)
	}
	if s.Protocol != "HTTP" && discoveryRe.MatchString(text) {
		add(T1082)
	}
	if minerRe.MatchString(text) {
		add(T1496)
	}

	out := make([]model.Technique, 0, len(set))
	for _, t := range set {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func PayloadEvidence(text string) bool {
	return soapRe.MatchString(text) || injectionRe.MatchString(text) || traversalRe.MatchString(text) || webExploitRe.MatchString(text)
}

func isWebExploit(path, text string, strict bool) bool {
	if PayloadEvidence(text) {
		return true
	}
	if strict {
		return false
	}
	lp := strings.ToLower(path)
	for _, frag := range exploitPaths {
		if strings.Contains(lp, frag) {
			return true
		}
	}
	return false
}
