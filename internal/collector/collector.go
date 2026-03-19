package collector

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"kyanos-lite/internal/model"
	"kyanos-lite/internal/parser"
	"kyanos-lite/internal/printer"
	"kyanos-lite/internal/store"
)

type endpoint struct {
	ip   string
	port uint16
}

type connKey struct {
	a endpoint
	b endpoint
}

type connState struct {
	ifName            string
	ifIndex           int
	lastSeen          time.Time
	client            endpoint
	server            endpoint
	role              string
	requestBuf        bytes.Buffer
	requestStartAt    time.Time
	responseBuf       bytes.Buffer
	currentResponseAt time.Time
	pending           []*model.PendingRequest
	seenPackets       map[string]time.Time
}

type Collector struct {
	cfg     model.Config
	streams map[connKey]*connState
	printer *printer.Printer
	store   *store.RedisStore
}

func New(cfg model.Config) *Collector {
	rs, _ := store.NewRedisStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.RedisListKey, cfg.RedisMaxItems)
	return &Collector{
		cfg:     cfg,
		streams: make(map[connKey]*connState),
		printer: printer.New(cfg.JSONOutput),
		store:   rs,
	}
}

func (c *Collector) Close() error {
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

func (c *Collector) HandlePacket(pkt model.PacketEvent) {
	if len(pkt.Payload) == 0 {
		return
	}
	key := canonicalKey(
		endpoint{ip: pkt.SrcIP, port: pkt.SrcPort},
		endpoint{ip: pkt.DstIP, port: pkt.DstPort},
	)
	st, ok := c.streams[key]
	if !ok {
		st = &connState{
			ifName:      pkt.IfName,
			ifIndex:     pkt.IfIndex,
			role:        "packet",
			seenPackets: make(map[string]time.Time),
		}
		c.streams[key] = st
	}
	st.ifName = pkt.IfName
	st.ifIndex = pkt.IfIndex
	st.lastSeen = pkt.Timestamp
	c.prunePending(st, pkt.Timestamp)

	if c.isDuplicate(st, pkt) {
		if c.cfg.Debug {
			log.Printf("[collector] duplicate packet ignored: %s:%d -> %s:%d seq=%d payload=%d",
				pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Seq, len(pkt.Payload))
		}
		c.gc(pkt.Timestamp)
		return
	}

	dir, ok := c.classify(pkt, st)
	if !ok {
		if c.cfg.Debug {
			log.Printf("[collector] packet not classified as http: %s:%d -> %s:%d payload=%d preview=%s",
				pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, len(pkt.Payload), previewBytes(pkt.Payload, 96))
		}
		c.gc(pkt.Timestamp)
		return
	}
	if c.cfg.Debug {
		log.Printf("[collector] classified=%s client=%s:%d server=%s:%d",
			dir, st.client.ip, st.client.port, st.server.ip, st.server.port)
	}
	switch dir {
	case "request":
		c.handleRequest(pkt, st)
	case "response":
		c.handleResponse(pkt, st)
	}
	c.gc(pkt.Timestamp)
}

func canonicalKey(a, b endpoint) connKey {
	if endpointLess(b, a) {
		a, b = b, a
	}
	return connKey{a: a, b: b}
}

func endpointLess(a, b endpoint) bool {
	if a.ip != b.ip {
		return a.ip < b.ip
	}
	return a.port < b.port
}

func (c *Collector) classify(pkt model.PacketEvent, st *connState) (string, bool) {
	src := endpoint{ip: pkt.SrcIP, port: pkt.SrcPort}
	dst := endpoint{ip: pkt.DstIP, port: pkt.DstPort}

	if st.client != (endpoint{}) && st.server != (endpoint{}) {
		if src == st.client && dst == st.server {
			return "request", true
		}
		if src == st.server && dst == st.client {
			return "response", true
		}
	}

	if c.cfg.PortFilter != 0 {
		switch {
		case pkt.DstPort == c.cfg.PortFilter:
			st.client = src
			st.server = dst
			return "request", true
		case pkt.SrcPort == c.cfg.PortFilter:
			st.client = dst
			st.server = src
			return "response", true
		}
	}

	switch {
	case parser.LooksLikeHTTPRequest(pkt.Payload):
		st.client = src
		st.server = dst
		return "request", true
	case parser.LooksLikeHTTPResponse(pkt.Payload):
		st.client = dst
		st.server = src
		return "response", true
	default:
		return "", false
	}
}

func (c *Collector) handleRequest(pkt model.PacketEvent, st *connState) {
	if st.requestBuf.Len() == 0 {
		idx := parser.FindRequestStart(pkt.Payload)
		if idx < 0 {
			if c.cfg.Debug {
				log.Printf("[collector] request start not found in payload preview=%s", previewBytes(pkt.Payload, 96))
			}
			return
		}
		pkt.Payload = pkt.Payload[idx:]
		st.requestStartAt = pkt.Timestamp
	}
	_, _ = st.requestBuf.Write(pkt.Payload)
	resyncRequestBuffer(&st.requestBuf)
	if st.requestBuf.Len() > 1024*1024 {
		st.requestBuf.Reset()
		st.requestStartAt = time.Time{}
		return
	}
	for {
		req, consumed, ok := parser.ExtractRequest(st.requestBuf.Bytes(), c.cfg.MaxBodyBytes)
		if !ok {
			if c.cfg.Debug {
				log.Printf("[collector] waiting for more request bytes: buffered=%d preview=%s",
					st.requestBuf.Len(), previewBytes(st.requestBuf.Bytes(), 96))
			}
			return
		}
		startAt := st.requestStartAt
		if startAt.IsZero() {
			startAt = pkt.Timestamp
		}
		st.pending = append(st.pending, &model.PendingRequest{
			ChainID:        chainID(st.client, st.server, startAt),
			RequestStartAt: startAt,
		})
		event := model.FlowRecord{
			ID:        fmt.Sprintf("%s-req-%d", st.client.ip, pkt.Timestamp.UnixNano()),
			ChainID:   st.pending[len(st.pending)-1].ChainID,
			Kind:      "request",
			When:      pkt.Timestamp,
			IfName:    st.ifName,
			IfIndex:   st.ifIndex,
			Role:      st.role,
			Tuple:     model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
			Request:   req,
			RequestAt: startAt,
		}
		c.printer.PrintFlow(event)
		_ = c.store.SaveFlow(event)
		if c.cfg.Debug {
			log.Printf("[collector] request parsed: method=%s path=%s host=%s bodyBytes=%d pending=%d",
				req.Method, req.Path, req.Host, req.BodyBytes, len(st.pending))
		}
		drainBuffer(&st.requestBuf, consumed)
		resyncRequestBuffer(&st.requestBuf)
		if st.requestBuf.Len() == 0 {
			st.requestStartAt = time.Time{}
			return
		}
		st.requestStartAt = pkt.Timestamp
	}
}

func (c *Collector) handleResponse(pkt model.PacketEvent, st *connState) {
	if st.responseBuf.Len() == 0 {
		idx := parser.FindResponseStart(pkt.Payload)
		if idx < 0 {
			if c.cfg.Debug {
				log.Printf("[collector] response start not found in payload preview=%s", previewBytes(pkt.Payload, 96))
			}
			return
		}
		pkt.Payload = pkt.Payload[idx:]
		st.currentResponseAt = pkt.Timestamp
	}
	if st.currentResponseAt.IsZero() {
		st.currentResponseAt = pkt.Timestamp
	}
	_, _ = st.responseBuf.Write(pkt.Payload)
	resyncResponseBuffer(&st.responseBuf)
	if st.responseBuf.Len() > 1024*1024 {
		st.responseBuf.Reset()
		st.currentResponseAt = time.Time{}
		return
	}
	for {
		resp, consumed, ok := parser.ExtractResponse(st.responseBuf.Bytes(), c.cfg.MaxBodyBytes)
		if !ok {
			if c.cfg.Debug {
				log.Printf("[collector] waiting for more response bytes: buffered=%d preview=%s",
					st.responseBuf.Len(), previewBytes(st.responseBuf.Bytes(), 96))
			}
			return
		}
		if len(st.pending) > 0 {
			pending := st.pending[0]
			st.pending = st.pending[1:]
			flow := model.FlowRecord{
				ID:            fmt.Sprintf("%s-resp-%d", st.server.ip, pkt.Timestamp.UnixNano()),
				ChainID:       pending.ChainID,
				Kind:          "response",
				When:          pkt.Timestamp,
				IfName:        st.ifName,
				IfIndex:       st.ifIndex,
				Role:          st.role,
				Tuple:         model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
				Response:      resp,
				RequestAt:     pending.RequestStartAt,
				ResponseAt:    st.currentResponseAt,
				ResponseEndAt: pkt.Timestamp,
			}
			if c.cfg.Debug {
				log.Printf("[collector] response parsed: status=%d bodyBytes=%d chain_id=%s",
					resp.StatusCode, resp.BodyBytes, flow.ChainID)
			}
			c.printer.PrintFlow(flow)
			_ = c.store.SaveFlow(flow)
		} else {
			if c.cfg.Debug {
				log.Printf("[collector] parsed response without pending request: status=%d preview=%s",
					resp.StatusCode, previewBytes(st.responseBuf.Bytes(), 96))
			}
			flow := model.FlowRecord{
				ID:            fmt.Sprintf("%s-orphan-resp-%d", st.server.ip, pkt.Timestamp.UnixNano()),
				ChainID:       chainID(st.client, st.server, pkt.Timestamp),
				Kind:          "response",
				When:          pkt.Timestamp,
				IfName:        st.ifName,
				IfIndex:       st.ifIndex,
				Role:          st.role,
				Tuple:         model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
				Response:      resp,
				ResponseAt:    st.currentResponseAt,
				ResponseEndAt: pkt.Timestamp,
			}
			c.printer.PrintFlow(flow)
			_ = c.store.SaveFlow(flow)
		}
		drainBuffer(&st.responseBuf, consumed)
		resyncResponseBuffer(&st.responseBuf)
		st.currentResponseAt = time.Time{}
		if st.responseBuf.Len() == 0 {
			return
		}
	}
}

func (c *Collector) isDuplicate(st *connState, pkt model.PacketEvent) bool {
	now := pkt.Timestamp
	key := fmt.Sprintf("%s:%d>%s:%d|%d|%d",
		pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Seq, len(pkt.Payload))
	if exp, ok := st.seenPackets[key]; ok && now.Before(exp) {
		return true
	}
	st.seenPackets[key] = now.Add(2 * time.Second)
	for k, exp := range st.seenPackets {
		if now.After(exp) {
			delete(st.seenPackets, k)
		}
	}
	return false
}

func (c *Collector) gc(now time.Time) {
	for k, st := range c.streams {
		if now.Sub(st.lastSeen) > 2*time.Minute {
			delete(c.streams, k)
		}
	}
}

func (c *Collector) prunePending(st *connState, now time.Time) {
	if len(st.pending) == 0 {
		return
	}
	const pendingTTL = 30 * time.Second
	kept := st.pending[:0]
	for _, p := range st.pending {
		if now.Sub(p.RequestStartAt) <= pendingTTL {
			kept = append(kept, p)
			continue
		}
		if c.cfg.Debug {
			log.Printf("[collector] drop stale pending request: chain_id=%s age=%s", p.ChainID, now.Sub(p.RequestStartAt))
		}
	}
	st.pending = kept
	const pendingCap = 1024
	if len(st.pending) > pendingCap {
		sort.Slice(st.pending, func(i, j int) bool {
			return st.pending[i].RequestStartAt.Before(st.pending[j].RequestStartAt)
		})
		dropped := len(st.pending) - pendingCap
		if c.cfg.Debug {
			for i := 0; i < dropped; i++ {
				log.Printf("[collector] drop overflow pending request: chain_id=%s", st.pending[i].ChainID)
			}
		}
		st.pending = append([]*model.PendingRequest(nil), st.pending[dropped:]...)
	}
}

func drainBuffer(buf *bytes.Buffer, n int) {
	b := buf.Bytes()
	if n >= len(b) {
		buf.Reset()
		return
	}
	rest := append([]byte(nil), b[n:]...)
	buf.Reset()
	_, _ = buf.Write(rest)
}

func resyncRequestBuffer(buf *bytes.Buffer) {
	if buf.Len() == 0 {
		return
	}
	b := buf.Bytes()
	if parser.LooksLikeHTTPRequest(b) {
		return
	}
	idx := parser.FindRequestStart(b)
	if idx <= 0 {
		return
	}
	drainBuffer(buf, idx)
}

func resyncResponseBuffer(buf *bytes.Buffer) {
	if buf.Len() == 0 {
		return
	}
	b := buf.Bytes()
	if parser.LooksLikeHTTPResponse(b) {
		return
	}
	idx := parser.FindResponseStart(b)
	if idx <= 0 {
		return
	}
	drainBuffer(buf, idx)
}

func previewBytes(b []byte, limit int) string {
	if len(b) == 0 {
		return `""`
	}
	if len(b) > limit {
		b = b[:limit]
	}
	var sb strings.Builder
	sb.Grow(len(b) + 2)
	sb.WriteByte('"')
	for _, c := range b {
		switch c {
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		default:
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteString(`\x`)
				sb.WriteString(strings.ToUpper(strconv.FormatUint(uint64(c), 16)))
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func chainID(client, server endpoint, t time.Time) string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		client.ip, client.port, server.ip, server.port, t.UnixNano())
}
