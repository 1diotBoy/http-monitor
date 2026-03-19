package parser

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"

	"kyanos-lite/internal/model"
)

var methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "), []byte("PATCH "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("TRACE "), []byte("CONNECT "),
}

func LooksLikeHTTPRequest(b []byte) bool {
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func LooksLikeHTTPResponse(b []byte) bool {
	return bytes.HasPrefix(b, []byte("HTTP/1."))
}

func FindRequestStart(b []byte) int {
	best := -1
	for _, m := range methods {
		if idx := bytes.Index(b, m); idx >= 0 && (best == -1 || idx < best) {
			best = idx
		}
	}
	return best
}

func FindResponseStart(b []byte) int {
	return bytes.Index(b, []byte("HTTP/1."))
}

func ExtractRequest(buf []byte, maxBody int) (model.HTTPRequest, int, bool) {
	msg, ok := extractHTTPMessage(buf, false)
	if !ok {
		return model.HTTPRequest{}, 0, false
	}
	req, ok := ParseRequest(msg, maxBody)
	if !ok {
		return model.HTTPRequest{}, 0, false
	}
	return req, len(msg), true
}

func ExtractResponse(buf []byte, maxBody int) (model.HTTPResponse, int, bool) {
	msg, ok := extractHTTPMessage(buf, true)
	if !ok {
		return model.HTTPResponse{}, 0, false
	}
	resp, ok := ParseResponse(msg, maxBody)
	if !ok {
		return model.HTTPResponse{}, 0, false
	}
	return resp, len(msg), true
}

func ParseRequest(raw []byte, maxBody int) (model.HTTPRequest, bool) {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return model.HTTPRequest{}, false
	}
	body, _ := readBodyLimited(maxBody, r.Body)
	body, _ = decodeBody(body, r.Header.Get("Content-Encoding"))
	return model.HTTPRequest{
		Method:        r.Method,
		Path:          r.URL.RequestURI(),
		Host:          r.Host,
		Header:        headerOnly(raw),
		Body:          safeBodyString(body),
		BodyBytes:     len(body),
		ContentLength: int(r.ContentLength),
		Chunked:       hasChunked(r.TransferEncoding),
		Raw:           safeBodyString(raw),
	}, true
}

func ParseResponse(raw []byte, maxBody int) (model.HTTPResponse, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return model.HTTPResponse{}, false
	}
	body, _ := readBodyLimited(maxBody, resp.Body)
	body, _ = decodeBody(body, resp.Header.Get("Content-Encoding"))
	return model.HTTPResponse{
		StatusLine:       strings.TrimSpace(resp.Proto + " " + resp.Status),
		StatusCode:       resp.StatusCode,
		Header:           headerOnly(raw),
		Body:             safeBodyString(body),
		BodyBytes:        len(body),
		ContentLength:    int(resp.ContentLength),
		TransferEncoding: strings.Join(resp.TransferEncoding, ","),
		Chunked:          hasChunked(resp.TransferEncoding),
		Upgrade:          resp.Header.Get("Upgrade"),
		Raw:              safeBodyString(raw),
	}, true
}

func extractHTTPMessage(buf []byte, isResp bool) ([]byte, bool) {
	headerEnd := headerEndIndex(buf)
	if headerEnd < 0 {
		return nil, false
	}
	headers := buf[:headerEnd]
	body := buf[headerEnd:]

	if isChunked(headers) {
		end, ok := chunkedBodyEnd(body)
		if !ok {
			return nil, false
		}
		return buf[:headerEnd+end], true
	}

	cl, hasCL := contentLength(headers)
	if isResp {
		status := parseStatusCode(headers)
		if status == 101 || status == 204 || status == 304 || (status >= 100 && status < 200) {
			return buf[:headerEnd], true
		}
	}
	if !hasCL {
		if isResp {
			return nil, false
		}
		return buf[:headerEnd], true
	}
	if len(body) < cl {
		return nil, false
	}
	return buf[:headerEnd+cl], true
}

func headerEndIndex(b []byte) int {
	if idx := bytes.Index(b, []byte("\r\n\r\n")); idx >= 0 {
		return idx + 4
	}
	if idx := bytes.Index(b, []byte("\n\n")); idx >= 0 {
		return idx + 2
	}
	return -1
}

func headerOnly(raw []byte) string {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return string(raw[:idx])
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return string(raw[:idx])
	}
	return string(raw)
}

func contentLength(headers []byte) (int, bool) {
	for _, line := range strings.Split(string(headers), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			v := strings.TrimSpace(parts[1])
			n, err := strconv.Atoi(v)
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func parseStatusCode(headers []byte) int {
	lineEnd := bytes.IndexByte(headers, '\n')
	if lineEnd < 0 {
		lineEnd = len(headers)
	}
	first := strings.TrimSpace(string(headers[:lineEnd]))
	parts := strings.Split(first, " ")
	if len(parts) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

func isChunked(headers []byte) bool {
	return strings.Contains(strings.ToLower(string(headers)), "transfer-encoding: chunked")
}

func hasChunked(v []string) bool {
	for _, s := range v {
		if strings.EqualFold(strings.TrimSpace(s), "chunked") {
			return true
		}
	}
	return false
}

func chunkedBodyEnd(body []byte) (int, bool) {
	offset := 0
	for {
		lineEnd := bytes.Index(body[offset:], []byte("\r\n"))
		sepLen := 2
		if lineEnd < 0 {
			lineEnd = bytes.Index(body[offset:], []byte("\n"))
			sepLen = 1
		}
		if lineEnd < 0 {
			return 0, false
		}
		line := strings.TrimSpace(string(body[offset : offset+lineEnd]))
		sizeHex := strings.Split(line, ";")[0]
		size, err := strconv.ParseInt(sizeHex, 16, 64)
		if err != nil {
			return 0, false
		}
		offset += lineEnd + sepLen
		if len(body[offset:]) < int(size)+sepLen {
			return 0, false
		}
		offset += int(size)
		if bytes.HasPrefix(body[offset:], []byte("\r\n")) {
			offset += 2
		} else if bytes.HasPrefix(body[offset:], []byte("\n")) {
			offset += 1
		} else {
			return 0, false
		}
		if size == 0 {
			for {
				if bytes.HasPrefix(body[offset:], []byte("\r\n")) {
					return offset + 2, true
				}
				if bytes.HasPrefix(body[offset:], []byte("\n")) {
					return offset + 1, true
				}
				trailEnd := bytes.Index(body[offset:], []byte("\r\n"))
				trailSep := 2
				if trailEnd < 0 {
					trailEnd = bytes.Index(body[offset:], []byte("\n"))
					trailSep = 1
				}
				if trailEnd < 0 {
					return 0, false
				}
				offset += trailEnd + trailSep
			}
		}
	}
}

func readBodyLimited(maxBody int, body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	if maxBody <= 0 {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(maxBody)))
	if err != nil {
		return nil, err
	}
	return data, nil
}

// decodeBody decompresses body when Content-Encoding is gzip or deflate,
// so safeBodyString can show plain text instead of "<binary body omitted>".
func decodeBody(body []byte, contentEncoding string) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	var r io.Reader
	switch {
	case enc == "gzip" || enc == "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		defer zr.Close()
		r = zr
	case enc == "deflate":
		zr, err := zlib.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, err
		}
		defer zr.Close()
		r = zr
	default:
		return body, nil
	}
	dec, err := io.ReadAll(r)
	if err != nil {
		return body, err // keep original on decompress error
	}
	return dec, nil
}

func safeBodyString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if isMostlyPrintableUTF8(b) {
		return string(b)
	}
	return "<binary body omitted>"
}

func isMostlyPrintableUTF8(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			printable++
		}
	}
	return printable*100/len(b) >= 85
}
