package model

import "time"

type PacketEvent struct {
	Timestamp time.Time
	IfIndex   int
	IfName    string
	PktType   uint8
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32
	Ack       uint32
	Payload   []byte
}

// FiveTuple preserves the original transport metadata even though chain_id is
// now an opaque transaction identifier.
type FiveTuple struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
}

// HTTPRequest keeps only the fields that are useful for downstream analysis
// and UI display.
type HTTPRequest struct {
	Method    string `json:"method"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Headers   string `json:"headers"`
	Body      string `json:"body"`
	BodyBytes int    `json:"body_bytes"`
}

// HTTPResponse mirrors the compact request view: status line, headers and body.
type HTTPResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status_code"`
	Headers    string `json:"headers"`
	Body       string `json:"body"`
	BodyBytes  int    `json:"body_bytes"`
}

// FlowRecord is the compact event schema shared by CLI output, Redis storage
// and the UI. Request and response are emitted as separate records.
type FlowRecord struct {
	ID            string        `json:"id"`
	ChainID       string        `json:"chain_id"`
	Kind          string        `json:"kind"`
	When          time.Time     `json:"when"`
	IfName        string        `json:"if_name"`
	IfIndex       int           `json:"if_index"`
	Tuple         FiveTuple     `json:"tuple"`
	Role          string        `json:"role"`
	RequestEndSeq uint32        `json:"request_end_seq,omitempty"`
	ResponseAck   uint32        `json:"response_ack,omitempty"`
	Request       *HTTPRequest  `json:"request,omitempty"`
	Response      *HTTPResponse `json:"response,omitempty"`
}

type Config struct {
	MaxBodyBytes       int
	JSONOutput         bool
	Debug              bool
	VerboseFlowLog     bool
	PortFilter         uint16
	Interface          string
	InterfaceIdx       int
	IPFilter           string
	Workers            int
	GOMAXPROCS         int
	SinkWorkers        int
	PacketQueueSize    int
	WorkerQueueSize    int
	FlowQueueSize      int
	SocketRcvBufMB     int
	RedisAddr          string
	RedisPassword      string
	RedisDB            int
	RedisListKey       string
	RedisMaxItems      int64
	RedisFailLog       string
	RedisWorkers       int
	RedisQueueSize     int
	RedisBatchSize     int
	RedisFlushInterval time.Duration
}
