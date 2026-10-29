package model

import (
	"strconv"
	"strings"
	"time"
)

type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (t Technique) String() string { return t.ID + " (" + t.Name + ")" }

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type IOCs struct {
	URLs         []string `json:"urls,omitempty"`
	DownloadURLs []string `json:"download_urls,omitempty"`
	IPs          []string `json:"ips,omitempty"`
	Domains      []string `json:"domains,omitempty"`
	NFS          []string `json:"nfs,omitempty"`
}

func (i IOCs) Empty() bool {
	return len(i.URLs) == 0 && len(i.IPs) == 0 && len(i.Domains) == 0 && len(i.NFS) == 0
}

type DownloadResult struct {
	URL         string    `json:"url"`
	Status      string    `json:"status"`
	Success     bool      `json:"success"`
	Cached      bool      `json:"cached,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	FileType    string    `json:"file_type,omitempty"`
	ContentType string    `json:"content_type,omitempty"`
	Size        int64     `json:"size,omitempty"`
	DurationMs  int64     `json:"duration_ms"`
	Timestamp   time.Time `json:"timestamp"`
}

type DroppedFile struct {
	Path       string    `json:"path"`
	Via        string    `json:"via"`
	Mode       string    `json:"mode,omitempty"`
	Status     string    `json:"status"`
	Success    bool      `json:"success"`
	Incomplete bool      `json:"incomplete,omitempty"`
	Executable bool      `json:"executable,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	Filename   string    `json:"filename,omitempty"`
	FileType   string    `json:"file_type,omitempty"`
	Size       int64     `json:"size,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

type Geo struct {
	Country     string `json:"country"`
	CountryCode string `json:"country_code,omitempty"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn,omitempty"`
	ASName      string `json:"as_name,omitempty"`
	Resolved    bool   `json:"resolved"`
}

type Event struct {
	ID                string           `json:"id"`
	Timestamp         time.Time        `json:"timestamp"`
	SrcIP             string           `json:"src_ip"`
	SrcPort           int              `json:"src_port"`
	DstPort           int              `json:"dst_port"`
	Protocol          string           `json:"protocol"`
	Action            string           `json:"action"`
	Signature         string           `json:"signature,omitempty"`
	Persona           string           `json:"persona,omitempty"`
	AbuseReported     bool             `json:"abuse_reported,omitempty"`
	HTTPMethod        string           `json:"http_method,omitempty"`
	HTTPPath          string           `json:"http_path,omitempty"`
	UserAgent         string           `json:"user_agent,omitempty"`
	Payload           string           `json:"payload,omitempty"`
	BytesReceived     int              `json:"bytes_received"`
	Truncated         bool             `json:"truncated,omitempty"`
	Commands          []string         `json:"commands,omitempty"`
	Credentials       []Credential     `json:"credentials,omitempty"`
	SessionDurationMs int64            `json:"session_duration_ms"`
	IOCs              IOCs             `json:"iocs"`
	Techniques        []Technique      `json:"mitre"`
	Downloads         []DownloadResult `json:"downloads,omitempty"`
	Dropped           []DroppedFile    `json:"dropped,omitempty"`
	Geo               Geo              `json:"geo"`
	AlertSent         bool             `json:"alert_sent"`

	Text string `json:"-"`
}

func (e *Event) Service() string {
	return strconv.Itoa(e.DstPort) + "/" + e.Protocol
}

func (e *Event) TechniqueIDs() []string {
	ids := make([]string, 0, len(e.Techniques))
	for _, t := range e.Techniques {
		ids = append(ids, t.ID)
	}
	return ids
}

func (e *Event) HasTechnique(id string) bool {
	for _, t := range e.Techniques {
		if strings.EqualFold(t.ID, id) {
			return true
		}
	}
	return false
}
