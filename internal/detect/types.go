package detect

// Kind classifies a detection finding.
type Kind string

const (
	KindIntel  Kind = "intel"
	KindExfil  Kind = "exfil"
	KindBeacon Kind = "beacon"
	KindDGA    Kind = "dga"
)

// Action is how the system disposed of the finding.
type Action string

const (
	ActionAlert   Action = "alert"   // logged only
	ActionBlocked Action = "blocked" // connection killed, not banned
	ActionBanned  Action = "banned"  // written to deny-list (implies kill when auto-block on)
)

// Event is one observed egress connection plus its detection verdict.
// Kept for the connection ring / history finalize sink; alerts also emit Detection.
type Event struct {
	ID          uint64   `json:"id"`
	Time        string   `json:"time"`
	Network     string   `json:"network"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Process     string   `json:"process"`
	Rule        string   `json:"rule"`
	Outbound    string   `json:"outbound"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Level       string   `json:"level"`            // "info" | "alert"
	Block       bool     `json:"block,omitempty"`  // auto-block eligible
	Denied      bool     `json:"denied,omitempty"` // routed to block outbound
	Reasons     []string `json:"reasons,omitempty"`

	// exfilEmitted avoids double Detection rows when mid-stream and finalize both see large upload.
	exfilEmitted bool
}

// Detection is one alert finding (intel / exfil / beacon / dga), durable via Store.
type Detection struct {
	ID          uint64   `json:"id"`
	Time        string   `json:"time"`
	Kind        Kind     `json:"kind"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Process     string   `json:"process,omitempty"`
	Upload      int64    `json:"upload,omitempty"`
	Download    int64    `json:"download,omitempty"`
	Action      Action   `json:"action"`
	Reasons     []string `json:"reasons,omitempty"`
	EventID     uint64   `json:"event_id,omitempty"`
}
