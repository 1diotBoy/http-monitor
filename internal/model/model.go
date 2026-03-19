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

type FiveTuple struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
}

type HTTPRequest struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Host          string `json:"host"`
	Header        string `json:"header"`
	Body          string `json:"body"`
	BodyBytes     int    `json:"body_bytes"`
	ContentLength int    `json:"content_length"`
	Chunked       bool   `json:"chunked"`
	Raw           string `json:"raw"`
}

type HTTPResponse struct {
	StatusLine       string `json:"status_line"`
	StatusCode       int    `json:"status_code"`
	Header           string `json:"header"`
	Body             string `json:"body"`
	BodyBytes        int    `json:"body_bytes"`
	ContentLength    int    `json:"content_length"`
	TransferEncoding string `json:"transfer_encoding"`
	Chunked          bool   `json:"chunked"`
	Upgrade          string `json:"upgrade"`
	Raw              string `json:"raw"`
}

type PendingRequest struct {
	ChainID        string
	RequestStartAt time.Time
}

type FlowRecord struct {
	ID            string        `json:"id"`
	ChainID       string        `json:"chain_id"`
	Kind          string        `json:"kind"`
	When          time.Time     `json:"when"`
	IfName        string        `json:"if_name"`
	IfIndex       int           `json:"if_index"`
	Tuple         FiveTuple     `json:"tuple"`
	Role          string        `json:"role"`
	Request       HTTPRequest   `json:"request"`
	Response      HTTPResponse  `json:"response"`
	RequestAt     time.Time     `json:"request_at"`
	ResponseAt    time.Time     `json:"response_at"`
	ResponseEndAt time.Time     `json:"response_end_at"`
	TTFB          time.Duration `json:"ttfb"`
	Total         time.Duration `json:"total"`
}

type Config struct {
	MaxBodyBytes  int
	JSONOutput    bool
	Debug         bool
	PortFilter    uint16
	Interface     string
	InterfaceIdx  int
	IPFilter      string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisListKey  string
	RedisMaxItems int64
}
