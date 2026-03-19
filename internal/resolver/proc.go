package resolver

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"kyanos-lite/internal/model"
)

type cacheEntry struct {
	tuple  model.FiveTuple
	expire time.Time
}

type ProcResolver struct {
	mu    sync.Mutex
	cache map[string]cacheEntry
	ttl   time.Duration
}

func New() *ProcResolver {
	return &ProcResolver{cache: make(map[string]cacheEntry), ttl: 5 * time.Second}
}

func (r *ProcResolver) Resolve(pid, fd uint32) model.FiveTuple {
	key := fmt.Sprintf("%d:%d", pid, fd)
	now := time.Now()
	r.mu.Lock()
	if ent, ok := r.cache[key]; ok && now.Before(ent.expire) {
		r.mu.Unlock()
		return ent.tuple
	}
	r.mu.Unlock()

	tuple := resolveFromProc(pid, fd)
	r.mu.Lock()
	r.cache[key] = cacheEntry{tuple: tuple, expire: now.Add(r.ttl)}
	r.mu.Unlock()
	return tuple
}

var socketRe = regexp.MustCompile(`socket:\[(\d+)\]`)

func resolveFromProc(pid, fd uint32) model.FiveTuple {
	linkPath := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	target, err := os.Readlink(linkPath)
	if err != nil {
		return model.FiveTuple{Protocol: "tcp"}
	}
	m := socketRe.FindStringSubmatch(target)
	if len(m) != 2 {
		return model.FiveTuple{Protocol: "tcp"}
	}
	inode := m[1]
	procRoot := fmt.Sprintf("/proc/%d/net", pid)
	if t, ok := findInProcNet(filepath.Join(procRoot, "tcp"), inode, false); ok {
		return t
	}
	if t, ok := findInProcNet(filepath.Join(procRoot, "tcp6"), inode, true); ok {
		return t
	}
	if t, ok := findInProcNet("/proc/net/tcp", inode, false); ok {
		return t
	}
	if t, ok := findInProcNet("/proc/net/tcp6", inode, true); ok {
		return t
	}
	return model.FiveTuple{Protocol: "tcp"}
}

func findInProcNet(path, inode string, isV6 bool) (model.FiveTuple, bool) {
	f, err := os.Open(path)
	if err != nil {
		return model.FiveTuple{}, false
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	first := true
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[9] != inode {
			continue
		}
		localIP, localPort, err1 := parseAddr(fields[1], isV6)
		remoteIP, remotePort, err2 := parseAddr(fields[2], isV6)
		if err1 != nil || err2 != nil {
			return model.FiveTuple{Protocol: "tcp"}, false
		}
		return model.FiveTuple{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			Protocol:   "tcp",
		}, true
	}
	return model.FiveTuple{}, false
}

func parseAddr(v string, isV6 bool) (string, uint16, error) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address")
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	port := uint16(port64)
	if !isV6 {
		raw, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			return "", 0, err
		}
		b := []byte{byte(raw), byte(raw >> 8), byte(raw >> 16), byte(raw >> 24)}
		return net.IPv4(b[0], b[1], b[2], b[3]).String(), port, nil
	}
	hex := parts[0]
	if len(hex) != 32 {
		return "", 0, fmt.Errorf("invalid ipv6 address")
	}
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0, err
		}
		b[15-i] = byte(v)
	}
	return net.IP(b).String(), port, nil
}
