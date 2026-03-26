package collector

import (
	"bytes"
	"testing"
	"time"

	"kyanos-lite/internal/model"
)

func TestAppendOrderedPayloadReordersOutOfOrderSegments(t *testing.T) {
	var buf bytes.Buffer
	fragments := make(map[uint32][]byte)
	var nextSeq uint32 = 100
	var ready = true

	if appended := appendOrderedPayload(&buf, fragments, &nextSeq, &ready, 105, []byte("world")); appended {
		t.Fatalf("unexpected append for out-of-order segment")
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer length = %d, want 0", buf.Len())
	}

	if appended := appendOrderedPayload(&buf, fragments, &nextSeq, &ready, 100, []byte("hello")); !appended {
		t.Fatalf("expected in-order append")
	}

	if got := buf.String(); got != "helloworld" {
		t.Fatalf("buffer = %q, want %q", got, "helloworld")
	}
}

func TestCollectorMatchesResponsesByFIFO(t *testing.T) {
	var flows []model.FlowRecord
	coll := NewWithEmitter(model.Config{
		PortFilter:   8080,
		MaxBodyBytes: 1024,
	}, func(flow model.FlowRecord) {
		flows = append(flows, flow)
	}, "test-instance")

	base := time.Unix(1710000000, 0)
	req1 := []byte("POST /a HTTP/1.1\r\nHost: svc.local:8080\r\nContent-Length: 1\r\n\r\nA")
	req2 := []byte("POST /b HTTP/1.1\r\nHost: svc.local:8080\r\nContent-Length: 1\r\n\r\nB")
	resp1 := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	resp2 := []byte("HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")

	coll.HandlePacket(model.PacketEvent{
		Timestamp: base,
		IfIndex:   2,
		IfName:    "eth0",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   50000,
		DstPort:   8080,
		Seq:       1000,
		Payload:   req1,
	})
	coll.HandlePacket(model.PacketEvent{
		Timestamp: base.Add(time.Millisecond),
		IfIndex:   2,
		IfName:    "eth0",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   50000,
		DstPort:   8080,
		Seq:       1000 + uint32(len(req1)),
		Payload:   req2,
	})
	// Both responses deliberately carry the same cumulative ACK to prove that
	// HTTP/1.x FIFO, not response_ack, drives the request/response pairing.
	coll.HandlePacket(model.PacketEvent{
		Timestamp: base.Add(2 * time.Millisecond),
		IfIndex:   2,
		IfName:    "eth0",
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   8080,
		DstPort:   50000,
		Seq:       9000,
		Ack:       1000 + uint32(len(req1)+len(req2)),
		Payload:   resp1,
	})
	coll.HandlePacket(model.PacketEvent{
		Timestamp: base.Add(3 * time.Millisecond),
		IfIndex:   2,
		IfName:    "eth0",
		SrcIP:     "10.0.0.2",
		DstIP:     "10.0.0.1",
		SrcPort:   8080,
		DstPort:   50000,
		Seq:       9000 + uint32(len(resp1)),
		Ack:       1000 + uint32(len(req1)+len(req2)),
		Payload:   resp2,
	})

	if len(flows) != 4 {
		t.Fatalf("flow count = %d, want 4", len(flows))
	}
	if flows[0].Kind != "request" || flows[1].Kind != "request" || flows[2].Kind != "response" || flows[3].Kind != "response" {
		t.Fatalf("unexpected flow kinds: %+v", []string{flows[0].Kind, flows[1].Kind, flows[2].Kind, flows[3].Kind})
	}
	if flows[0].ChainID == flows[1].ChainID {
		t.Fatalf("request chain ids should be unique, both were %q", flows[0].ChainID)
	}
	if flows[0].ChainID != flows[2].ChainID {
		t.Fatalf("resp1 chain_id = %q, want %q", flows[2].ChainID, flows[0].ChainID)
	}
	if flows[1].ChainID != flows[3].ChainID {
		t.Fatalf("resp2 chain_id = %q, want %q", flows[3].ChainID, flows[1].ChainID)
	}
}
