package parser

import "testing"

func TestSafeBodyStringAcceptsUTF8Text(t *testing.T) {
	body := []byte(`{"msg":"并发响应正常"}`)
	if got := safeBodyString(body); got != string(body) {
		t.Fatalf("safeBodyString() = %q, want %q", got, string(body))
	}
}
