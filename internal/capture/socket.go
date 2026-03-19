package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"kyanos-lite/internal/model"
)

type PacketSocket struct {
	iface *Interface
	file  *os.File
	fd    int
	debug bool
}

type Interface struct {
	Index int
	Name  string
}

func OpenPacketSocket(ifaceName string, debug bool) (*PacketSocket, error) {
	if ifaceName == "" {
		return nil, fmt.Errorf("iface is required")
	}
	rawIfIndex, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/ifindex", ifaceName))
	if err != nil {
		return nil, fmt.Errorf("resolve iface %q: %w", ifaceName, err)
	}
	ifIndex, err := strconv.Atoi(strings.TrimSpace(string(rawIfIndex)))
	if err != nil {
		return nil, fmt.Errorf("parse iface %q ifindex: %w", ifaceName, err)
	}
	iface := &Interface{Name: ifaceName, Index: ifIndex}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("open packet socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set receive buffer: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 0); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("enable outgoing packets: %w", err)
	}
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind packet socket: %w", err)
	}
	return &PacketSocket{
		iface: iface,
		file:  os.NewFile(uintptr(fd), fmt.Sprintf("packet-%s", iface.Name)),
		fd:    fd,
		debug: debug,
	}, nil
}

func (s *PacketSocket) File() *os.File {
	return s.file
}

func (s *PacketSocket) Interface() *Interface {
	return s.iface
}

func (s *PacketSocket) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *PacketSocket) ReadLoop(ctx context.Context, out chan<- model.PacketEvent) error {
	buf := make([]byte, 64*1024)
	for {
		n, sa, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, unix.EBADF) {
				return nil
			}
			return fmt.Errorf("recv packet: %w", err)
		}
		lla, ok := sa.(*unix.SockaddrLinklayer)
		if !ok {
			if s.debug {
				log.Printf("[capture] recvfrom returned non-linklayer sockaddr: %T", sa)
			}
			continue
		}
		pkt, ok := decodeIPv4Packet(buf[:n], s.iface, uint8(lla.Pkttype))
		if !ok {
			if s.debug {
				log.Printf("[capture] raw packet dropped by decoder: iface=%s pktType=%d len=%d preview=%s",
					s.iface.Name, lla.Pkttype, n, previewBytes(buf[:n], 96))
			}
			continue
		}
		select {
		case out <- pkt:
		case <-ctx.Done():
			return nil
		}
	}
}

func decodeIPv4Packet(buf []byte, iface *Interface, pktType uint8) (model.PacketEvent, bool) {
	l3Off, ok := ipv4Offset(buf)
	if !ok {
		return model.PacketEvent{}, false
	}
	buf = buf[l3Off:]
	if len(buf) < 20 {
		return model.PacketEvent{}, false
	}
	if buf[0]>>4 != 4 {
		return model.PacketEvent{}, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || len(buf) < ihl+20 {
		return model.PacketEvent{}, false
	}
	if buf[9] != unix.IPPROTO_TCP {
		return model.PacketEvent{}, false
	}
	frag := binary.BigEndian.Uint16(buf[6:8])
	if frag&0x1fff != 0 {
		return model.PacketEvent{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if totalLen > len(buf) {
		totalLen = len(buf)
	}
	tcpOff := ihl
	dataOff := int(buf[tcpOff+12]>>4) * 4
	if dataOff < 20 || totalLen < tcpOff+dataOff {
		return model.PacketEvent{}, false
	}
	payload := append([]byte(nil), buf[tcpOff+dataOff:totalLen]...)
	if len(payload) == 0 {
		return model.PacketEvent{}, false
	}
	return model.PacketEvent{
		Timestamp: time.Now(),
		IfIndex:   iface.Index,
		IfName:    iface.Name,
		PktType:   pktType,
		SrcIP:     fmt.Sprintf("%d.%d.%d.%d", buf[12], buf[13], buf[14], buf[15]),
		DstIP:     fmt.Sprintf("%d.%d.%d.%d", buf[16], buf[17], buf[18], buf[19]),
		SrcPort:   binary.BigEndian.Uint16(buf[tcpOff : tcpOff+2]),
		DstPort:   binary.BigEndian.Uint16(buf[tcpOff+2 : tcpOff+4]),
		Seq:       binary.BigEndian.Uint32(buf[tcpOff+4 : tcpOff+8]),
		Ack:       binary.BigEndian.Uint32(buf[tcpOff+8 : tcpOff+12]),
		Payload:   payload,
	}, true
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func ipv4Offset(buf []byte) (int, bool) {
	if len(buf) < 14 {
		return 0, false
	}
	etherType := binary.BigEndian.Uint16(buf[12:14])
	switch etherType {
	case unix.ETH_P_IP:
		return 14, true
	case unix.ETH_P_8021Q, unix.ETH_P_8021AD:
		if len(buf) < 18 {
			return 0, false
		}
		inner := binary.BigEndian.Uint16(buf[16:18])
		if inner != unix.ETH_P_IP {
			return 0, false
		}
		return 18, true
	default:
		return 0, false
	}
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
