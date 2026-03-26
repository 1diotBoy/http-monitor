#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_PACKET_SIZE 65535

typedef struct filter_config_t {
    __u32 ifindex;
    __u32 ip4;
    __u16 port;
    __u8 enable_ifindex;
    __u8 enable_ip;
    __u8 enable_port;
    __u8 pad[3];
} filter_config_t;

struct vlan_hdr_t {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct bpf_map_def SEC("maps") filter_config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(filter_config_t),
    .max_entries = 1,
};

static __always_inline __u16 bpf_htons16(__u16 v) {
    return __builtin_bswap16(v);
}

static __always_inline __u16 bpf_ntohs16(__u16 v) {
    return __builtin_bswap16(v);
}

SEC("socket")
int filter_packets(struct __sk_buff *skb) {
    /*
     * This program does only cheap packet selection in-kernel:
     *   1. verify iface / IPv4 / TCP
     *   2. appxly user-provided iface / port / IP filters
     *   3. return packet length to keep the frame, or 0 to drop it
     *
     * HTTP parsing stays in user space so the same binary can run on older
     * kernels such as 4.19 without relying on newer eBPF helpers or ringbuf.
     */
    __u32 key = 0;
    filter_config_t *cfg = bpf_map_lookup_elem(&filter_config, &key);
    if (!cfg) {
        return 0;
    }

    if (cfg->enable_ifindex) {
        /*
         * On some kernels / directions, packet socket skb metadata may carry
         * only one of ifindex / ingress_ifindex, or both may be zero for
         * locally generated egress packets. The socket itself is already bound
         * to the target iface, so only reject when kernel metadata is present
         * and explicitly disagrees with the requested iface.
         */
        if ((skb->ifindex || skb->ingress_ifindex) &&
            skb->ifindex != cfg->ifindex &&
            skb->ingress_ifindex != cfg->ifindex) {
            return 0;
        }
    }

    struct ethhdr eth = {};
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return 0;
    }
    __u32 l3_off = sizeof(struct ethhdr);
    __u16 proto = eth.h_proto;
    if (proto == bpf_htons16(ETH_P_8021Q) || proto == bpf_htons16(ETH_P_8021AD)) {
        struct vlan_hdr_t vlan = {};
        if (bpf_skb_load_bytes(skb, l3_off, &vlan, sizeof(vlan)) < 0) {
            return 0;
        }
        proto = vlan.h_vlan_encapsulated_proto;
        l3_off += sizeof(vlan);
    }
    if (proto != bpf_htons16(ETH_P_IP)) {
        return 0;
    }

    struct iphdr iph = {};
    if (bpf_skb_load_bytes(skb, l3_off, &iph, sizeof(iph)) < 0) {
        return 0;
    }
    if (iph.version != 4 || iph.protocol != IPPROTO_TCP) {
        return 0;
    }

    __u32 ihl = (__u32)iph.ihl * 4;
    if (ihl < sizeof(struct iphdr)) {
        return 0;
    }

    if (cfg->enable_ip) {
        if (iph.saddr != cfg->ip4 && iph.daddr != cfg->ip4) {
            return 0;
        }
    }

    struct tcphdr tcph = {};
    __u32 l4_off = l3_off + ihl;
    if (bpf_skb_load_bytes(skb, l4_off, &tcph, sizeof(tcph)) < 0) {
        return 0;
    }

    if (cfg->enable_port) {
        __u16 target = bpf_htons16(cfg->port);
        if (tcph.source != target && tcph.dest != target) {
            return 0;
        }
    }

    __u32 thl = (__u32)tcph.doff * 4;
    if (thl < sizeof(struct tcphdr)) {
        return 0;
    }
    if ((__u32)bpf_ntohs16(iph.tot_len) <= ihl + thl) {
        return 0;
    }

    if (skb->len > MAX_PACKET_SIZE) {
        return MAX_PACKET_SIZE;
    }
    return skb->len;
}
