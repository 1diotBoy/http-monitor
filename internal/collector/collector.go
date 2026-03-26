package collector

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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

type txnToken struct {
	txnSeq        uint64
	requestEndSeq uint32
	enqueuedAt    time.Time
	skip          bool
}

// connState keeps the minimum state needed to reassemble TCP payloads into
// HTTP/1.x messages and preserve FIFO request/response ordering.
type connState struct {
	ifName             string
	ifIndex            int
	connID             uint64
	requestTxnSeq      uint64
	responseTxnSeq     uint64
	lastSeen           time.Time
	client             endpoint
	server             endpoint
	role               string
	requestBuf         bytes.Buffer
	requestStartAt     time.Time
	requestStartSeq    uint32
	requestNextSeq     uint32
	requestSeqReady    bool
	requestFragments   map[uint32][]byte
	responseBuf        bytes.Buffer
	currentResponseAt  time.Time
	currentResponseAck uint32
	responseNextSeq    uint32
	responseSeqReady   bool
	responseFragments  map[uint32][]byte
	pending            []txnToken
	pendingHead        int
	seenPackets        map[string]time.Time
}

type Collector struct {
	cfg          model.Config
	streams      map[connKey]*connState
	printer      *printer.Printer
	store        *store.RedisStore
	emit         func(model.FlowRecord)
	instanceID   string
	nextConnID   atomic.Uint64
	nextOrphanID atomic.Uint64
	ownsStore    bool
}

func New(cfg model.Config) *Collector {
	rs, _ := store.NewRedisStore(
		cfg.RedisAddr,
		cfg.RedisPassword,
		cfg.RedisDB,
		cfg.RedisListKey,
		cfg.RedisMaxItems,
		cfg.RedisFailLog,
		cfg.RedisWorkers,
		cfg.RedisQueueSize,
		cfg.RedisBatchSize,
		cfg.RedisFlushInterval,
	)
	c := &Collector{
		cfg:        cfg,
		streams:    make(map[connKey]*connState),
		printer:    printer.New(cfg.JSONOutput, cfg.VerboseFlowLog),
		store:      rs,
		instanceID: fmt.Sprintf("%x", time.Now().UnixNano()),
		ownsStore:  true,
	}
	c.emit = c.emitSync
	return c
}

func NewWithDeps(cfg model.Config, pr *printer.Printer, st *store.RedisStore, instanceID string) *Collector {
	if pr == nil {
		pr = printer.New(cfg.JSONOutput, cfg.VerboseFlowLog)
	}
	if instanceID == "" {
		instanceID = fmt.Sprintf("%x", time.Now().UnixNano())
	}
	c := &Collector{
		cfg:        cfg,
		streams:    make(map[connKey]*connState),
		printer:    pr,
		store:      st,
		instanceID: instanceID,
	}
	c.emit = c.emitSync
	return c
}

func NewWithEmitter(cfg model.Config, emit func(model.FlowRecord), instanceID string) *Collector {
	if instanceID == "" {
		instanceID = fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return &Collector{
		cfg:        cfg,
		streams:    make(map[connKey]*connState),
		emit:       emit,
		instanceID: instanceID,
	}
}

func (c *Collector) Close() error {
	if c.ownsStore && c.store != nil {
		return c.store.Close()
	}
	return nil
}

func (c *Collector) HandlePacket(pkt model.PacketEvent) {
	if len(pkt.Payload) == 0 {
		return
	}
	// All packets for the same TCP connection share one connState, regardless of
	// direction. The key is canonicalized so request and response hit the same
	// buffers and the same per-connection transaction counters.
	key := canonicalKey(
		endpoint{ip: pkt.SrcIP, port: pkt.SrcPort},
		endpoint{ip: pkt.DstIP, port: pkt.DstPort},
	)
	st, ok := c.streams[key]
	if !ok {
		st = &connState{
			ifName:            pkt.IfName,
			ifIndex:           pkt.IfIndex,
			connID:            c.nextConnID.Add(1),
			role:              "packet",
			requestFragments:  make(map[uint32][]byte),
			responseFragments: make(map[uint32][]byte),
			seenPackets:       make(map[string]time.Time),
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

// handleRequest appends payload into the request-side reassembly buffer. Once a
// full HTTP message is available, it emits a standalone request event.
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
		st.requestStartSeq = pkt.Seq + uint32(idx)
		st.requestNextSeq = st.requestStartSeq
		st.requestSeqReady = true
	}
	if appended := appendOrderedPayload(&st.requestBuf, st.requestFragments, &st.requestNextSeq, &st.requestSeqReady, st.requestStartSeqForPacket(pkt), pkt.Payload); appended {
		resyncRequestBuffer(&st.requestBuf)
	}
	if st.requestBuf.Len() > 1024*1024 {
		st.requestBuf.Reset()
		st.requestStartAt = time.Time{}
		st.requestStartSeq = 0
		st.requestNextSeq = 0
		st.requestSeqReady = false
		clear(st.requestFragments)
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
		reqEndSeq := st.requestStartSeq + uint32(consumed)
		st.requestTxnSeq++
		txnSeq := st.requestTxnSeq
		chainID := c.chainIDForTxn(st.connID, txnSeq)
		skip := shouldSkipStaticResource(req.Path)
		st.pushPending(txnToken{
			txnSeq:        txnSeq,
			requestEndSeq: reqEndSeq,
			enqueuedAt:    startAt,
			skip:          skip,
		}, c.cfg.Debug, c.instanceID, st.connID)
		if skip {
			if c.cfg.Debug {
				log.Printf("[collector] skip static request: method=%s path=%s chain_id=%s req_end_seq=%d pending=%d request_txn=%d response_txn=%d",
					req.Method, req.Path, chainID, reqEndSeq, st.pendingLen(), st.requestTxnSeq, st.responseTxnSeq)
			}
		} else {
			event := model.FlowRecord{
				ID:            fmt.Sprintf("%s-req-%d", st.client.ip, startAt.UnixNano()),
				ChainID:       chainID,
				Kind:          "request",
				When:          startAt,
				IfName:        st.ifName,
				IfIndex:       st.ifIndex,
				Role:          st.role,
				Tuple:         model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
				RequestEndSeq: reqEndSeq,
				Request:       &req,
			}
			c.emitFlow(event)
			if c.cfg.Debug {
				log.Printf("[collector] request parsed: method=%s url=%s bodyBytes=%d chain_id=%s req_end_seq=%d pending=%d request_txn=%d response_txn=%d",
					req.Method, req.URL, req.BodyBytes, chainID, reqEndSeq, st.pendingLen(), st.requestTxnSeq, st.responseTxnSeq)
			}
		}
		drainBuffer(&st.requestBuf, consumed)
		resyncRequestBuffer(&st.requestBuf)
		if st.requestBuf.Len() == 0 {
			resetRequestStream(st)
			return
		}
		st.requestStartAt = pkt.Timestamp
		st.requestStartSeq = reqEndSeq
	}
}

// handleResponse mirrors handleRequest. Responses pop the oldest outstanding
// request token from the connection-local FIFO, which matches HTTP/1.x ordering
// while keeping only tiny metadata per in-flight transaction.
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
		st.currentResponseAck = pkt.Ack
		st.responseNextSeq = pkt.Seq + uint32(idx)
		st.responseSeqReady = true
	}
	if st.currentResponseAt.IsZero() {
		st.currentResponseAt = pkt.Timestamp
	}
	if appended := appendOrderedPayload(&st.responseBuf, st.responseFragments, &st.responseNextSeq, &st.responseSeqReady, st.responseSeqForPacket(pkt), pkt.Payload); appended {
		resyncResponseBuffer(&st.responseBuf)
	}
	if st.responseBuf.Len() > 1024*1024 {
		st.responseBuf.Reset()
		st.currentResponseAt = time.Time{}
		st.currentResponseAck = 0
		st.responseNextSeq = 0
		st.responseSeqReady = false
		clear(st.responseFragments)
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
		if token, ok := st.popPending(); ok {
			st.responseTxnSeq = token.txnSeq
			if token.skip {
				if c.cfg.Debug {
					log.Printf("[collector] skip static response: chain_id=%s response_ack=%d status=%d pending=%d request_txn=%d response_txn=%d",
						c.chainIDForTxn(st.connID, token.txnSeq), st.currentResponseAck, resp.StatusCode, st.pendingLen(), st.requestTxnSeq, st.responseTxnSeq)
				}
				drainBuffer(&st.responseBuf, consumed)
				resyncResponseBuffer(&st.responseBuf)
				resetResponseMessage(st)
				if st.responseBuf.Len() == 0 {
					return
				}
				continue
			}
			if c.cfg.Debug && token.requestEndSeq != 0 && st.currentResponseAck != 0 && st.currentResponseAck < token.requestEndSeq {
				log.Printf("[collector] transport hint mismatch: chain_id=%s request_end_seq=%d response_ack=%d",
					c.chainIDForTxn(st.connID, token.txnSeq), token.requestEndSeq, st.currentResponseAck)
			}
			flow := model.FlowRecord{
				ID:          fmt.Sprintf("%s-resp-%d", st.server.ip, st.currentResponseAt.UnixNano()),
				ChainID:     c.chainIDForTxn(st.connID, token.txnSeq),
				Kind:        "response",
				When:        st.currentResponseAt,
				IfName:      st.ifName,
				IfIndex:     st.ifIndex,
				Role:        st.role,
				Tuple:       model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
				ResponseAck: st.currentResponseAck,
				Response:    &resp,
			}
			if c.cfg.Debug {
				log.Printf("[collector] response parsed: status=%d bodyBytes=%d chain_id=%s response_ack=%d pending=%d request_txn=%d response_txn=%d",
					resp.StatusCode, resp.BodyBytes, flow.ChainID, flow.ResponseAck, st.pendingLen(), st.requestTxnSeq, st.responseTxnSeq)
			}
			c.emitFlow(flow)
		} else {
			if c.cfg.Debug {
				log.Printf("[collector] parsed response without outstanding request: status=%d response_ack=%d preview=%s",
					resp.StatusCode, st.currentResponseAck, previewBytes(st.responseBuf.Bytes(), 96))
			}
			flow := model.FlowRecord{
				ID:          fmt.Sprintf("%s-orphan-resp-%d", st.server.ip, st.currentResponseAt.UnixNano()),
				ChainID:     c.newOrphanChainID(),
				Kind:        "response",
				When:        st.currentResponseAt,
				IfName:      st.ifName,
				IfIndex:     st.ifIndex,
				Role:        st.role,
				Tuple:       model.FiveTuple{LocalIP: st.client.ip, LocalPort: st.client.port, RemoteIP: st.server.ip, RemotePort: st.server.port, Protocol: "tcp"},
				ResponseAck: st.currentResponseAck,
				Response:    &resp,
			}
			c.emitFlow(flow)
		}
		drainBuffer(&st.responseBuf, consumed)
		resyncResponseBuffer(&st.responseBuf)
		resetResponseMessage(st)
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
	if st.pendingLen() == 0 {
		return
	}
	const pendingTTL = 2 * time.Minute
	for st.pendingLen() > 0 {
		token := st.pending[st.pendingHead]
		if now.Sub(token.enqueuedAt) <= pendingTTL {
			break
		}
		if c.cfg.Debug {
			log.Printf("[collector] drop stale pending txn: chain_id=%s age=%s skip=%v",
				c.chainIDForTxn(st.connID, token.txnSeq), now.Sub(token.enqueuedAt), token.skip)
		}
		st.pending[st.pendingHead] = txnToken{}
		st.pendingHead++
	}
	st.compactPending()
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

// appendOrderedPayload turns packet-level TCP payloads into a contiguous byte
// stream. It trims retransmitted overlap, buffers gaps and flushes buffered
// out-of-order fragments once the missing bytes arrive.
func appendOrderedPayload(buf *bytes.Buffer, fragments map[uint32][]byte, nextSeq *uint32, ready *bool, seq uint32, payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	if !*ready {
		*nextSeq = seq
		*ready = true
	}
	if seq < *nextSeq {
		overlap := int(*nextSeq - seq)
		if overlap >= len(payload) {
			return false
		}
		payload = payload[overlap:]
		seq = *nextSeq
	}
	if seq > *nextSeq {
		storeFragment(fragments, seq, payload)
		return false
	}
	_, _ = buf.Write(payload)
	*nextSeq += uint32(len(payload))
	flushOrderedFragments(buf, fragments, nextSeq)
	return true
}

func storeFragment(fragments map[uint32][]byte, seq uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}
	if existing, ok := fragments[seq]; ok && len(existing) >= len(payload) {
		return
	}
	fragments[seq] = append([]byte(nil), payload...)
}

func flushOrderedFragments(buf *bytes.Buffer, fragments map[uint32][]byte, nextSeq *uint32) {
	for {
		if len(fragments) == 0 {
			return
		}
		keys := make([]uint32, 0, len(fragments))
		for seq := range fragments {
			keys = append(keys, seq)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

		progressed := false
		for _, seq := range keys {
			payload := fragments[seq]
			endSeq := seq + uint32(len(payload))
			if endSeq <= *nextSeq {
				delete(fragments, seq)
				continue
			}
			if seq > *nextSeq {
				return
			}
			if seq < *nextSeq {
				payload = payload[int(*nextSeq-seq):]
			}
			_, _ = buf.Write(payload)
			*nextSeq += uint32(len(payload))
			delete(fragments, seq)
			progressed = true
		}
		if !progressed {
			return
		}
	}
}

func resetRequestStream(st *connState) {
	st.requestStartAt = time.Time{}
	st.requestStartSeq = 0
	st.requestNextSeq = 0
	st.requestSeqReady = false
	clear(st.requestFragments)
}

func resetResponseMessage(st *connState) {
	st.currentResponseAt = time.Time{}
	st.currentResponseAck = 0
	if st.responseBuf.Len() == 0 {
		st.responseNextSeq = 0
		st.responseSeqReady = false
		clear(st.responseFragments)
	}
}

func (st *connState) requestStartSeqForPacket(pkt model.PacketEvent) uint32 {
	if st.requestBuf.Len() == 0 && st.requestSeqReady {
		return st.requestStartSeq
	}
	return pkt.Seq
}

func (st *connState) responseSeqForPacket(pkt model.PacketEvent) uint32 {
	if st.responseBuf.Len() == 0 && st.responseSeqReady {
		return st.responseNextSeq
	}
	return pkt.Seq
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

func (c *Collector) chainIDForTxn(connID, txnSeq uint64) string {
	return fmt.Sprintf("%s-%016x-%016x", c.instanceID, connID, txnSeq)
}

func (c *Collector) newOrphanChainID() string {
	seq := c.nextOrphanID.Add(1)
	return fmt.Sprintf("%s-orphan-%016x", c.instanceID, seq)
}

func (st *connState) pushPending(token txnToken, debug bool, instanceID string, connID uint64) {
	st.pending = append(st.pending, token)
	const maxPendingPerConn = 4096
	if st.pendingLen() <= maxPendingPerConn {
		return
	}
	dropped := st.pending[st.pendingHead]
	st.pending[st.pendingHead] = txnToken{}
	st.pendingHead++
	st.compactPending()
	if debug {
		log.Printf("[collector] drop oldest pending txn due to cap: chain_id=%s pending=%d",
			fmt.Sprintf("%s-%016x-%016x", instanceID, connID, dropped.txnSeq), st.pendingLen())
	}
}

func (st *connState) popPending() (txnToken, bool) {
	if st.pendingLen() == 0 {
		return txnToken{}, false
	}
	token := st.pending[st.pendingHead]
	st.pending[st.pendingHead] = txnToken{}
	st.pendingHead++
	st.compactPending()
	return token, true
}

func (st *connState) pendingLen() int {
	return len(st.pending) - st.pendingHead
}

func (st *connState) compactPending() {
	if st.pendingHead == 0 {
		return
	}
	if st.pendingHead < len(st.pending)/2 && st.pendingHead < 1024 {
		return
	}
	st.pending = append([]txnToken(nil), st.pending[st.pendingHead:]...)
	st.pendingHead = 0
}

func shouldSkipStaticResource(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	if idx := strings.IndexByte(path, '#'); idx >= 0 {
		path = path[:idx]
	}
	path = strings.ToLower(path)
	for _, suffix := range []string{
		".js", ".css", ".jpg", ".jpeg", ".png",
		".gif", ".svg", ".ico", ".webp", ".map",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
	} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func (c *Collector) emitFlow(flow model.FlowRecord) {
	if c.emit != nil {
		c.emit(flow)
		return
	}
	c.emitSync(flow)
}

func (c *Collector) emitSync(flow model.FlowRecord) {
	if c.printer != nil {
		c.printer.PrintFlow(flow)
	}
	if c.store != nil {
		_ = c.store.SaveFlow(flow)
	}
}
