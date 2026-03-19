package printer

import (
	"encoding/json"
	"fmt"
	"strings"

	"kyanos-lite/internal/model"
)

type Printer struct {
	jsonOutput bool
}

func New(jsonOutput bool) *Printer {
	return &Printer{jsonOutput: jsonOutput}
}

func (p *Printer) PrintFlow(flow model.FlowRecord) {
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
	if !flow.RequestAt.IsZero() {
		fmt.Printf("request_at=%s\n", flow.RequestAt.Format("2006-01-02 15:04:05.000"))
	}
	if !flow.ResponseAt.IsZero() {
		fmt.Printf("response_at=%s\n", flow.ResponseAt.Format("2006-01-02 15:04:05.000"))
	}
	if !flow.ResponseEndAt.IsZero() {
		fmt.Printf("response_end_at=%s\n", flow.ResponseEndAt.Format("2006-01-02 15:04:05.000"))
	}
	switch flow.Kind {
	case "request":
		fmt.Printf("request:  %s %s", flow.Request.Method, flow.Request.Path)
		if flow.Request.Host != "" {
			fmt.Printf(" host=%s", flow.Request.Host)
		}
		fmt.Println()
		fmt.Println("--- request headers ---")
		fmt.Println(flow.Request.Header)
		printBody("request body", flow.Request.Body, flow.Request.BodyBytes)
	case "response":
		fmt.Printf("response: %s\n", flow.Response.StatusLine)
		if flow.Response.Upgrade != "" || flow.Response.StatusCode == 101 {
			fmt.Printf("upgrade:  %s\n", flow.Response.Upgrade)
		}
		fmt.Println("--- response headers ---")
		fmt.Println(flow.Response.Header)
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
