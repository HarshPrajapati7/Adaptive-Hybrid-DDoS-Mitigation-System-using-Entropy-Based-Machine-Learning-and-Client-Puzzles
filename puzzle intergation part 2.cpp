#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CMS_ROWS 4
#define CMS_COLS 1024
#define PUZZLE_SECRET 0x1337CAFE

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CMS_ROWS * CMS_COLS);
    __type(key, __u32);
    __type(value, __u64);
} count_min_sketch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} blacklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} challenge_map SEC(".maps");

static __always_inline __u32 hash(__u32 value, __u32 seed) {
    value ^= seed;
    value *= 0x5bd1e995;
    value ^= value >> 15;
    return value;
}

static __always_inline __u32 generate_cookie(__u32 saddr) {
    return hash(saddr, PUZZLE_SECRET);
}

SEC("xdp")
int vajra_engine(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Packet Parsing
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u32 src_ip = ip->saddr;

    // 2. Blacklist Check
    __u8 *blocked = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (blocked) return XDP_DROP;

    // 3. Update Statistics
    for (int i = 0; i < CMS_ROWS; i++) {
        __u32 idx = (hash(src_ip, i * 100) % CMS_COLS) + (i * CMS_COLS);
        __u64 *count = bpf_map_lookup_elem(&count_min_sketch, &idx);
        if (count) *count += 1;
    }

    // 4. Challenge Logic
    __u8 *challenge_active = bpf_map_lookup_elem(&challenge_map, &src_ip);
    if (challenge_active && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;

        // A. Send Puzzle (SYN Cookie)
        if (tcp->syn && !tcp->ack) {
            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

            __u32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            __u16 tmp_port = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = tmp_port;

            tcp->ack = 1;
            tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
            tcp->seq = bpf_htonl(generate_cookie(src_ip));

            ip->check = 0;
            tcp->check = 0;

            return XDP_TX;
        }

        // B. Verify Puzzle Answer
        if (tcp->ack && !tcp->syn) {
            __u32 expected = generate_cookie(src_ip);
            __u32 actual = bpf_ntohl(tcp->ack_seq) - 1;

            if (actual == expected) {
                bpf_map_delete_elem(&challenge_map, &src_ip);
                return XDP_PASS;
            } else {
                __u8 one = 1;
                bpf_map_update_elem(&blacklist_map, &src_ip, &one, BPF_ANY);
                return XDP_DROP;
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";