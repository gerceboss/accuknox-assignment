#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ptrace.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "GPL";

// Helper macros from reference code
#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
        _val;                                                                                  \
    })

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)

// Event structure (matching Go code)
struct info {
    __u32 pid;
    char comm[16];
    __u16 lport;
};

// Event map to store process bind events
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct info);
} eventmap SEC(".maps");

// Statistics map - track by port and PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // Combined key: (port << 16) | pid
    __type(value, __u64); // Count
} stats SEC(".maps");

// Port to PID mapping
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16); // Port
    __type(value, __u32); // PID
} port_to_pid SEC(".maps");

// No additional maps needed for Go style

// Configuration constants
const volatile char TARGET_COMM[16] = "myprocess";
const volatile __u16 TARGET_PORT = 5050;


// Kprobe to intercept socket bind operations (Go style)
SEC("kprobe/security_socket_bind")
int bind_intercept(struct pt_regs *ctx) {
    struct sockaddr *addr = (struct sockaddr *) ctx->rsi;
    
    // Get current process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Only capture our target process
    bool is_target = 1;
    for (int i = 0; i < 16 && TARGET_COMM[i] != '\0'; i++) {
        if (comm[i] != TARGET_COMM[i]) {
            is_target = 0;
            break;
        }
    }
    
    if (!is_target) {
        return 0; // Not our target process
    }
    
    // Read the bound port
    struct sockaddr_in *in_addr = (struct sockaddr_in *) addr;
    __u16 lport = READ_KERN(in_addr->sin_port);
    lport = bpf_ntohs(lport);
    
    // Store event in map (only for our target process)
    struct info event = {
        .pid = pid,
        .lport = lport
    };
    __builtin_memcpy(event.comm, comm, sizeof(comm));
    
    __u32 key = 0;
    bpf_map_update_elem(&eventmap, &key, &event, BPF_ANY);
    
    // Also store port to PID mapping for XDP program
    if (lport > 0) {
        bpf_map_update_elem(&port_to_pid, &lport, &pid, BPF_ANY);
    }
    
    return 0;
}

// XDP program to filter incoming traffic
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Get destination port
    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    // Check if this matches our target port
    if (dest_port == TARGET_PORT) {
        // Get the PID for this port from the port-to-PID mapping
        __u32 *pid = bpf_map_lookup_elem(&port_to_pid, &dest_port);
        if (pid) {
            // Create combined key: (port << 16) | pid
            __u32 combined_key = (dest_port << 16) | *pid;
            
            // Increment statistics for this port+pid combination
            __u64 *count = bpf_map_lookup_elem(&stats, &combined_key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            } else {
                __u64 initial_count = 1;
                bpf_map_update_elem(&stats, &combined_key, &initial_count, BPF_ANY);
            }
        } else {
            // Fallback: just track by port if no PID info available
            __u32 port_key = dest_port;
            __u64 *count = bpf_map_lookup_elem(&stats, &port_key);
            if (count) {
                __sync_fetch_and_add(count, 1);
            } else {
                __u64 initial_count = 1;
                bpf_map_update_elem(&stats, &port_key, &initial_count, BPF_ANY);
            }
        }
        
        return XDP_PASS; // Allow traffic to target process
    }
    
    return XDP_PASS; // Allow all other traffic
}
