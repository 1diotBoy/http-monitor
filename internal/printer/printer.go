package printer

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"kyanos-lite/internal/model"
)

type Printer struct {
	jsonOutput bool
	enabled    bool
	mu         sync.Mutex
}

func New(jsonOutput, enabled bool) *Printer {
	return &Printer{jsonOutput: jsonOutput, enabled: enabled}
}

func (p *Printer) PrintFlow(flow model.FlowRecord) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jsonOutput {
		b, _ := json.Marshal(flow)
		fmt.Println(string(b))
		return
	}
	fmt.Println(strings.Repeat("=", 120))
	fmt.Printf("time=%s iface=%s(%d) kind=%s chain_id=%s role=%s\n",
		flow.When.Format("2006-01-02 15:04:05.000"), flow.IfName, flow.IfIndex, flow.Kind, flow.ChainID, flow.Role)
	fmt.Printf("tuple=%s:%d -> %s:%d proto=%s\n",
		flow.Tuple.LocalIP, flow.Tuple.LocalPort, flow.Tuple.RemoteIP, flow.Tuple.RemotePort, flow.Tuple.Protocol)
	if flow.RequestEndSeq != 0 {
		fmt.Printf("request_end_seq=%d\n", flow.RequestEndSeq)
	}
	if flow.ResponseAck != 0 {
		fmt.Printf("response_ack=%d\n", flow.ResponseAck)
	}
	switch flow.Kind {
	case "request":
		if flow.Request == nil {
			fmt.Println("request: <empty>")
			return
		}
		fmt.Printf("request:  %s %s\n", flow.Request.Method, flow.Request.URL)
		fmt.Println()
		fmt.Println("--- request headers ---")
		fmt.Println(flow.Request.Headers)
		printBody("request body", flow.Request.Body, flow.Request.BodyBytes)
	case "response":
		if flow.Response == nil {
			fmt.Println("response: <empty>")
			return
		}
		fmt.Printf("response: %s\n", flow.Response.Status)
		fmt.Println("--- response headers ---")
		fmt.Println(flow.Response.Headers)
		printBody("response body", flow.Response.Body, flow.Response.BodyBytes)
	default:
		fmt.Println("unknown flow kind")
	}
}

func printBody(title, body string, n int) {
	fmt.Printf("--- %s (%d bytes) ---\n", title, n)
	if n == 0 {
		fmt.Println("<empty>")
		return
	}
	fmt.Println(body)
}
