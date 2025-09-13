// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/resource.h>
#include <linux/if_link.h>

static struct bpf_object *obj = NULL;
static int ifindex = -1;
static bool running = true;

// Signal handler for graceful shutdown
static void sig_handler(int sig)
{
    printf("\nShutting down...\n");
    running = false;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit");
        exit(1);
    }
}

// Function to show statistics
static void show_stats(void)
{
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    if (stats_fd < 0) {
        printf("Could not find stats map\n");
        return;
    }
    
    __u16 port;
    __u64 count;
    int ret;
    
    printf("\n=== Statistics ===\n");
    printf("Port\tDropped Packets\n");
    printf("----\t---------------\n");
    
    // Iterate through all entries in stats map
    __u16 next_port = 0;
    while (bpf_map_get_next_key(stats_fd, &next_port, &port) == 0) {
        ret = bpf_map_lookup_elem(stats_fd, &port, &count);
        if (ret == 0) {
            printf("%u\t%llu\n", port, count);
        }
        next_port = port;
    }
    printf("==================\n\n");
}

// Function to add port to blocked list
static int add_blocked_port(__u16 port)
{
    int blocked_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ports");
    if (blocked_fd < 0) {
        fprintf(stderr, "Could not find blocked_ports map\n");
        return -1;
    }
    
    __u32 value = 1;
    int ret = bpf_map_update_elem(blocked_fd, &port, &value, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "Failed to add port %u to blocked list: %s\n", 
                port, strerror(-ret));
        return -1;
    }
    
    printf("Added port %u to blocked list\n", port);
    return 0;
}

// Function to parse comma-separated port list
static int parse_ports(const char *port_str, __u16 *ports, int max_ports)
{
    char *str = strdup(port_str);
    char *token;
    int count = 0;
    
    if (!str) {
        fprintf(stderr, "Failed to allocate memory\n");
        return -1;
    }
    
    token = strtok(str, ",");
    while (token && count < max_ports) {
        long port = strtol(token, NULL, 10);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", token);
            free(str);
            return -1;
        }
        ports[count++] = (__u16)port;
        token = strtok(NULL, ",");
    }
    
    free(str);
    return count;
}

// Function to print usage
static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\nOptions:\n");
    printf("  -i, --interface IF  Network interface to attach to (default: lo)\n");
    printf("  -p, --port PORT     Port number(s) to block (comma-separated)\n");
    printf("  -s, --stats         Show statistics\n");
    printf("  -u, --unload        Unload the eBPF program\n");
    printf("  -h, --help          Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -i lo -p 4040                    # Block port 4040 on loopback\n", prog_name);
    printf("  %s -i eth0 -p 4040,8080,9000        # Block multiple ports on eth0\n", prog_name);
    printf("  %s -s                               # Show statistics\n", prog_name);
    printf("  %s -u                               # Unload program\n", prog_name);
}

int main(int argc, char **argv)
{
    int opt, ret;
    char *interface = "lo";
    char *port_str = NULL;
    bool show_stats_only = false;
    bool unload_only = false;
    __u16 ports[64];
    int port_count = 0;
    
    // Long options
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"stats", no_argument, 0, 's'},
        {"unload", no_argument, 0, 'u'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "i:p:suh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'p':
            port_str = optarg;
            break;
        case 's':
            show_stats_only = true;
            break;
        case 'u':
            unload_only = true;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Get interface index
    ifindex = if_nametoindex(interface);
    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", interface);
        return 1;
    }
    
    // Handle unload only
    if (unload_only) {
        printf("Unloading XDP program from interface %s...\n", interface);
        // For unload, we need to detach any existing XDP program
        int ret = bpf_xdp_detach(ifindex, 0, NULL);
        if (ret < 0) {
            perror("bpf_xdp_detach");
            return 1;
        }
        printf("XDP program unloaded successfully\n");
        return 0;
    }
    
    // Handle stats only (need to load object first)
    if (show_stats_only) {
        bump_memlock_rlimit();
        
        obj = bpf_object__open_file("xdp_drop_port.o", NULL);
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "Failed to open BPF object\n");
            return 1;
        }
        
        if (bpf_object__load(obj)) {
            fprintf(stderr, "Failed to load BPF object\n");
            return 1;
        }
        
        show_stats();
        bpf_object__close(obj);
        return 0;
    }
    
    // Bump memory limits
    bump_memlock_rlimit();
    
    // Open the compiled XDP object file
    obj = bpf_object__open_file("xdp_drop_port.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }
    
    // Find program by section name
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_drop_port");
    if (!prog) {
        fprintf(stderr, "Program not found in object\n");
        return 1;
    }
    
    // Attach XDP program to interface
    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-libbpf_get_error(link)));
        return 1;
    }
    
    printf("XDP program loaded on interface %s\n", interface);
    
    // Parse and add ports
    if (port_str) {
        port_count = parse_ports(port_str, ports, sizeof(ports) / sizeof(ports[0]));
        if (port_count < 0) {
            ret = -1;
            goto cleanup;
        }
        
        for (int i = 0; i < port_count; i++) {
            if (add_blocked_port(ports[i]) < 0) {
                ret = -1;
                goto cleanup;
            }
        }
    }
    
    printf("TCP packet dropper is running. Press Ctrl+C to stop.\n");
    if (port_count > 0) {
        printf("Blocking TCP packets on port(s): ");
        for (int i = 0; i < port_count; i++) {
            printf("%u", ports[i]);
            if (i < port_count - 1) printf(", ");
        }
        printf("\n");
    }
    
    // Main loop - show stats periodically
    while (running) {
        sleep(5);
        if (running) {
            show_stats();
        }
    }
    
cleanup:
    // Detach XDP program
    if (ifindex > 0) {
        bpf_xdp_detach(ifindex, 0, NULL);
    }
    
    if (obj) {
        bpf_object__close(obj);
    }
    
    return ret;
}