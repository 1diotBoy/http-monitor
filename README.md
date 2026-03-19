# kyanos-lite

一个面向低版本 Linux 内核的简化版 HTTP 明文观测器。

当前实现参考了 `hengyoush/kyanos` 的“内核态先过滤、用户态再解析”思路，但保持了更小的代码体量：

- 内核态使用 `socket filter` 只放行目标网卡上的 IPv4 TCP 包
- 用户态按 TCP payload 重组 HTTP/1.x 请求与响应
- 请求和响应分开打印，并通过 `chain_id` 关联
- 支持打印 URL、请求头、响应头、请求体、响应体，以及请求/响应时间戳
- 支持通过 `--iface`、`--port`、`--ip` 将过滤参数下发到内核态
- 避开 `ringbuf` 依赖，构建产物更适合 4.19.x 这类低版本内核

## 限制

- 只支持 HTTP/1.x 明文流量
- 当前只支持 IPv4
- 当前只支持指定单个网卡抓包
- 当前不做 TLS/HTTPS 解密
- 当前按到达顺序拼接 TCP payload，适合本机调试、内网排障和常见 HTTP 场景，不是完整的 TCP 重传/乱序重组器
- pending 请求会按 TTL 和队列上限自动淘汰，避免长时间不返回响应时内存持续增长

## 构建

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev linux-libc-dev linux-headers-$(uname -r)
GOCACHE=/tmp/go-build-cache make build
```

## 运行

抓本机回环 HTTP 服务：

```bash
sudo ./bin/kyanos-lite --iface lo --port 12581
```

抓物理网卡上的 HTTP 服务：

```bash
sudo ./bin/kyanos-lite --iface eth0 --port 8080
```

抓某个目标 IP 的 HTTP 流量：

```bash
sudo ./bin/kyanos-lite --iface eth0 --port 8080 --ip 192.168.1.10
```

JSON 输出：

```bash
sudo ./bin/kyanos-lite --iface eth0 --port 8080 --json
```

## 实现概览

1. `bpf/http_trace.bpf.c`
   内核态 `socket filter`，按网卡/端口/IP 过滤 IPv4 TCP 包，只放行带应用层 payload 的数据包。

2. `internal/capture/socket.go`
   用户态打开 `AF_PACKET` 套接字并绑定网卡，挂载 eBPF filter，读取被放行的 IP 包。

3. `internal/collector/collector.go`
   以连接为单位维护请求缓冲区、响应缓冲区和 pending request 队列，匹配请求/响应并计算时延。

4. `internal/parser/http.go`
   负责 HTTP message 边界提取、gzip/deflate 解压、文本安全打印。
