package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"kyanos-lite/internal/capture"
	"kyanos-lite/internal/collector"
	"kyanos-lite/internal/model"
	"kyanos-lite/internal/printer"
	"kyanos-lite/internal/store"
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
	defaultCPU := runtime.NumCPU()
	defaultSinkWorkers := maxInt(1, defaultCPU/2)

	// CLI flags configure both kernel-side packet filtering and user-space
	// parsing / output behaviour.
	flag.IntVar(&cfg.MaxBodyBytes, "max-body-bytes", 4096, "max request/response body bytes to print, 0 disables body output")
	flag.BoolVar(&cfg.JSONOutput, "json", false, "print JSON lines")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable verbose debug logs")
	flag.BoolVar(&cfg.VerboseFlowLog, "verbose-flow-log", false, "print full request/response records to stdout")
	flag.UintVar(&port, "port", 12581, "match source OR destination port")
	flag.StringVar(&cfg.Interface, "iface", "ens32", "capture network interface, for example eth0 or lo")
	flag.StringVar(&cfg.IPFilter, "ip", "", "match source OR destination IPv4")
	flag.IntVar(&cfg.GOMAXPROCS, "gomaxprocs", defaultCPU, "GOMAXPROCS target / CPU cores used by Go schedulers")
	flag.IntVar(&cfg.Workers, "workers", defaultCPU, "number of packet processing workers")
	flag.IntVar(&cfg.SinkWorkers, "sink-workers", defaultSinkWorkers, "number of flow sink workers")
	flag.IntVar(&cfg.PacketQueueSize, "packet-queue-size", 131072, "queue size between capture loop and dispatcher")
	flag.IntVar(&cfg.WorkerQueueSize, "worker-queue-size", 16384, "per-worker packet queue size")
	flag.IntVar(&cfg.FlowQueueSize, "flow-queue-size", 65536, "queue size between collectors and sinks")
	flag.IntVar(&cfg.SocketRcvBufMB, "socket-rcvbuf-mb", 64, "packet socket receive buffer size in MiB")
	flag.StringVar(&cfg.RedisAddr, "redis-addr", "", "redis address, e.g. 127.0.0.1:6379")
	flag.StringVar(&cfg.RedisPassword, "redis-password", "", "redis password")
	flag.IntVar(&cfg.RedisDB, "redis-db", 0, "redis db")
	flag.StringVar(&cfg.RedisListKey, "redis-key", "kyanos:flows", "redis list key for saved flows")
	flag.Int64Var(&cfg.RedisMaxItems, "redis-max-items", 0, "max number of flow items to keep in redis list, 0 disables trimming")
	flag.StringVar(&cfg.RedisFailLog, "redis-fail-log", "kyanos-redis-failures.log", "log file for redis save failures and dropped flow counters")
	flag.IntVar(&cfg.RedisWorkers, "redis-workers", defaultSinkWorkers, "number of async redis writer workers")
	flag.IntVar(&cfg.RedisQueueSize, "redis-queue-size", 65536, "queue size for async redis writes")
	flag.IntVar(&cfg.RedisBatchSize, "redis-batch-size", 128, "number of flow records per redis batch flush")
	flag.DurationVar(&cfg.RedisFlushInterval, "redis-flush-interval", 20*time.Millisecond, "max wait before flushing a partial redis batch")
	flag.Parse()
	cfg.PortFilter = uint16(port)
	if cfg.GOMAXPROCS <= 0 {
		cfg.GOMAXPROCS = defaultCPU
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultCPU
	}
	if cfg.SinkWorkers <= 0 {
		cfg.SinkWorkers = defaultSinkWorkers
	}
	if cfg.PacketQueueSize <= 0 {
		cfg.PacketQueueSize = 131072
	}
	if cfg.WorkerQueueSize <= 0 {
		cfg.WorkerQueueSize = 16384
	}
	if cfg.FlowQueueSize <= 0 {
		cfg.FlowQueueSize = 65536
	}
	if cfg.SocketRcvBufMB <= 0 {
		cfg.SocketRcvBufMB = 64
	}
	if cfg.RedisWorkers <= 0 {
		cfg.RedisWorkers = defaultSinkWorkers
	}
	if cfg.RedisQueueSize <= 0 {
		cfg.RedisQueueSize = 65536
	}
	if cfg.RedisBatchSize <= 0 {
		cfg.RedisBatchSize = 128
	}
	if cfg.RedisFlushInterval <= 0 {
		cfg.RedisFlushInterval = 20 * time.Millisecond
	}
	runtime.GOMAXPROCS(cfg.GOMAXPROCS)

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	fmt.Println("kyanos-lite starting...")
	fmt.Printf("mode=packet-http json=%v debug=%v verbose-flow-log=%v gomaxprocs=%d workers=%d sink-workers=%d packet-queue=%d worker-queue=%d flow-queue=%d socket-rcvbuf-mb=%d max-body-bytes=%d iface=%s port=%d ip=%s redis=%s redis-key=%s redis-max-items=%d redis-workers=%d redis-queue=%d redis-batch-size=%d redis-flush-interval=%s redis-fail-log=%s\n",
		cfg.JSONOutput, cfg.Debug, cfg.VerboseFlowLog, cfg.GOMAXPROCS, cfg.Workers, cfg.SinkWorkers, cfg.PacketQueueSize, cfg.WorkerQueueSize, cfg.FlowQueueSize, cfg.SocketRcvBufMB, cfg.MaxBodyBytes, cfg.Interface, cfg.PortFilter, cfg.IPFilter, cfg.RedisAddr, cfg.RedisListKey, cfg.RedisMaxItems, cfg.RedisWorkers, cfg.RedisQueueSize, cfg.RedisBatchSize, cfg.RedisFlushInterval, cfg.RedisFailLog)

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
	// Strip embedded BTF metadata so the same object can still load on older
	// kernels such as 4.19 that may not have usable in-kernel BTF.
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

	sock, err := capture.OpenPacketSocket(cfg.Interface, cfg.Debug, cfg.SocketRcvBufMB<<20)
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
	// The eBPF socket filter runs first and drops packets that do not match the
	// selected iface / port / IP, so user space only sees relevant TCP payloads.
	if err := link.AttachSocketFilter(sock.File(), objs.FilterPackets); err != nil {
		log.Fatalf("attach socket filter: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = sock.Close()
	}()

	sharedStore, _ := store.NewRedisStore(
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
	if sharedStore != nil {
		defer sharedStore.Close()
	}
	sharedPrinter := printer.New(cfg.JSONOutput, cfg.VerboseFlowLog)
	// Flow emission is decoupled from packet parsing so Redis / stdout I/O does
	// not stall the TCP reassembly workers under load.
	flowCh := make(chan model.FlowRecord, cfg.FlowQueueSize)
	var sinkWG sync.WaitGroup
	for i := 0; i < cfg.SinkWorkers; i++ {
		sinkWG.Add(1)
		go func() {
			defer sinkWG.Done()
			for flow := range flowCh {
				sharedPrinter.PrintFlow(flow)
				if sharedStore != nil {
					_ = sharedStore.SaveFlow(flow)
				}
			}
		}()
	}
	workerCollectors := make([]*collector.Collector, 0, cfg.Workers)
	workerChans := make([]chan model.PacketEvent, 0, cfg.Workers)
	var workerWG sync.WaitGroup
	instancePrefix := fmt.Sprintf("%x", time.Now().UnixNano())
	for i := 0; i < cfg.Workers; i++ {
		// One collector owns one shard of TCP connections. A connection always
		// hashes to the same worker, which preserves HTTP/1.x FIFO semantics.
		emit := func(flow model.FlowRecord) {
			flowCh <- flow
		}
		coll := collector.NewWithEmitter(cfg, emit, fmt.Sprintf("%s-%02d", instancePrefix, i))
		ch := make(chan model.PacketEvent, cfg.WorkerQueueSize)
		workerCollectors = append(workerCollectors, coll)
		workerChans = append(workerChans, ch)
		workerWG.Add(1)
		go func(coll *collector.Collector, ch <-chan model.PacketEvent) {
			defer workerWG.Done()
			for pkt := range ch {
				coll.HandlePacket(pkt)
			}
		}(coll, ch)
	}
	defer func() {
		for _, ch := range workerChans {
			close(ch)
		}
		workerWG.Wait()
		close(flowCh)
		sinkWG.Wait()
		for _, coll := range workerCollectors {
			_ = coll.Close()
		}
	}()

	packetCh := make(chan model.PacketEvent, cfg.PacketQueueSize)
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
			// Packets are sharded by canonical 5-tuple, so one TCP connection
			// always stays on one worker and keeps its FIFO semantics.
			workerChans[shardPacket(pkt, cfg.Workers)] <- pkt
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

func shardPacket(pkt model.PacketEvent, workers int) int {
	if workers <= 1 {
		return 0
	}
	aIP, aPort := pkt.SrcIP, pkt.SrcPort
	bIP, bPort := pkt.DstIP, pkt.DstPort
	if endpointGreater(aIP, aPort, bIP, bPort) {
		aIP, bIP = bIP, aIP
		aPort, bPort = bPort, aPort
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(aIP))
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], aPort)
	_, _ = h.Write(portBuf[:])
	_, _ = h.Write([]byte(bIP))
	binary.BigEndian.PutUint16(portBuf[:], bPort)
	_, _ = h.Write(portBuf[:])
	return int(h.Sum32() % uint32(workers))
}

func endpointGreater(aIP string, aPort uint16, bIP string, bPort uint16) bool {
	if aIP != bIP {
		return aIP > bIP
	}
	return aPort > bPort
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
