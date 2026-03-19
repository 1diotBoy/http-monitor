package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"kyanos-lite/internal/capture"
	"kyanos-lite/internal/collector"
	"kyanos-lite/internal/model"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -cc clang -cflags "-O2 -Wall -Werror -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu" HttpTrace ../../bpf/http_trace.bpf.c -- -I../../bpf

type kernelFilterConfig struct {
	Ifindex       uint32
	Ip4           uint32
	Port          uint16
	EnableIfindex uint8
	EnableIp      uint8
	EnablePort    uint8
	Pad           [3]uint8
}

func main() {
	var cfg model.Config
	var port uint

	flag.IntVar(&cfg.MaxBodyBytes, "max-body-bytes", 4096, "max request/response body bytes to print, 0 disables body output")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "print JSON lines")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable verbose debug logs")
	flag.UintVar(&port, "port", 12581, "match source OR destination port")
	flag.StringVar(&cfg.Interface, "iface", "ens32", "capture network interface, for example eth0 or lo")
	flag.StringVar(&cfg.IPFilter, "ip", "", "match source OR destination IPv4")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", "", "redis address, e.g. 127.0.0.1:6379")
	flag.StringVar(&cfg.RedisPassword, "redis-password", "", "redis password")
	flag.IntVar(&cfg.RedisDB, "redis-db", 0, "redis db")
	flag.StringVar(&cfg.RedisListKey, "redis-key", "kyanos:flows", "redis list key for saved flows")
	flag.Int64Var(&cfg.RedisMaxItems, "redis-max-items", 2000, "max number of flow items to keep in redis list")
	flag.Parse()
	cfg.PortFilter = uint16(port)

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	fmt.Println("kyanos-lite starting...")
	fmt.Printf("mode=packet-http json=%v debug=%v max-body-bytes=%d iface=%s port=%d ip=%s redis=%s redis-key=%s\n",
		cfg.JSONOutput, cfg.Debug, cfg.MaxBodyBytes, cfg.Interface, cfg.PortFilter, cfg.IPFilter, cfg.RedisAddr, cfg.RedisListKey)

	if os.Geteuid() != 0 {
		log.Fatal("please run as root")
	}
	if cfg.Interface == "" {
		log.Fatal("please set --iface")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	spec, err := LoadHttpTrace()
	if err != nil {
		log.Fatalf("load bpf spec: %v", err)
	}
	// Strip embedded BTF metadata so the object can still load on older kernels.
	spec.Types = nil

	objs := HttpTraceObjects{}
	loadOpts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     1,
			LogSizeStart: 1 << 20,
		},
	}
	if err := spec.LoadAndAssign(&objs, loadOpts); err != nil {
		log.Fatalf("load bpf objects: %v", err)
	}
	defer objs.Close()

	sock, err := capture.OpenPacketSocket(cfg.Interface, cfg.Debug)
	if err != nil {
		log.Fatalf("open capture socket: %v", err)
	}
	defer sock.Close()

	cfg.InterfaceIdx = sock.Interface().Index
	kcfg, err := buildKernelConfig(cfg)
	if err != nil {
		log.Fatalf("build kernel config: %v", err)
	}
	if cfg.Debug {
		log.Printf("[debug] packet socket opened: iface=%s ifindex=%d", cfg.Interface, cfg.InterfaceIdx)
		log.Printf("[debug] kernel filter config: ifindex=%d port=%d ip=%s flags(if=%d,port=%d,ip=%d)",
			kcfg.Ifindex, kcfg.Port, cfg.IPFilter, kcfg.EnableIfindex, kcfg.EnablePort, kcfg.EnableIp)
	}
	key := uint32(0)
	if err := objs.FilterConfig.Update(&key, &kcfg, ebpf.UpdateAny); err != nil {
		log.Fatalf("update filter config: %v", err)
	}
	if err := link.AttachSocketFilter(sock.File(), objs.FilterPackets); err != nil {
		log.Fatalf("attach socket filter: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = sock.Close()
	}()

	coll := collector.New(cfg)
	defer coll.Close()

	packetCh := make(chan model.PacketEvent, 8192)
	errCh := make(chan error, 1)
	go func() {
		errCh <- sock.ReadLoop(ctx, packetCh)
	}()

	fmt.Println("socket filter attached successfully, waiting for HTTP packets...")

	for {
		select {
		case pkt := <-packetCh:
			if cfg.Debug {
				log.Printf("[capture] iface=%s pktType=%d %s:%d -> %s:%d payload=%d seq=%d ack=%d preview=%s",
					pkt.IfName, pkt.PktType, pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort,
					len(pkt.Payload), pkt.Seq, pkt.Ack, previewBytes(pkt.Payload, 96))
			}
			coll.HandlePacket(pkt)
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Fatalf("capture loop: %v", err)
			}
			fmt.Println("stopped")
			return
		case <-ctx.Done():
			fmt.Println("stopped")
			return
		}
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

func buildKernelConfig(cfg model.Config) (kernelFilterConfig, error) {
	kcfg := kernelFilterConfig{
		Ifindex: uint32(cfg.InterfaceIdx),
		Port:    cfg.PortFilter,
	}
	if cfg.InterfaceIdx != 0 {
		kcfg.EnableIfindex = 1
	}
	if cfg.PortFilter != 0 {
		kcfg.EnablePort = 1
	}
	if cfg.IPFilter != "" {
		ip := net.ParseIP(cfg.IPFilter).To4()
		if ip == nil {
			return kernelFilterConfig{}, fmt.Errorf("only IPv4 is supported for --ip")
		}
		kcfg.Ip4 = binary.BigEndian.Uint32(ip)
		kcfg.EnableIp = 1
	}
	return kcfg, nil
}
