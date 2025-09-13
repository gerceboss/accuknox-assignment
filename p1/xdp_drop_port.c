// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

// BPF map to store blocked ports
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16); // 16-bit port number
    __type(value, __u32); 
} blocked_ports SEC(".maps");

// BPF map to store statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);
    __type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_drop_port(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Check if we have enough data for ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    
    struct ethhdr *eth = data;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Check if we have enough data for IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(struct ethhdr);
    
    // Check if it's a TCP packet
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Check if we have enough data for TCP header
    if (data + sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;
    
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + (iph->ihl * 4);
    
    // Get destination port in host byte order
    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    // Check if this port is blocked
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ports, &dest_port);
    if (!blocked)
        return XDP_PASS;
    
    // Update statistics atomically
    __u64 *count = bpf_map_lookup_elem(&stats, &dest_port);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&stats, &dest_port, &initial_count, BPF_ANY);
    }
    
    // Drop the packet
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";