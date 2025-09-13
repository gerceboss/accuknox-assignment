#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <net/if.h>

static struct bpf_object *obj = NULL;
static bool running = true;

// Event structure
struct info {
    __u32 pid;
    char comm[16];
    __u16 lport;
};

// Signal handler
static void sig_handler(int sig) {
    printf("\nShutting down...\n");
    running = false;
}

static void bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(1);
    }
}

pid_t get_pid_by_name(const char *proc_name) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s", proc_name);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    int pid = -1;
    fscanf(fp, "%d", &pid);
    pclose(fp);
    return pid;
}

int main(int argc, char **argv) {
    char *proc_name = "myprocess";
    int target_port = 5050;
    
    if (argc > 1) {
        proc_name = argv[1];
    }
    if (argc > 2) {
        target_port = atoi(argv[2]);
    }
    
    printf("Process Port Filter - Monitoring traffic for specific process\n");
    printf("Target process: %s\n", proc_name);
    printf("Target port: %d\n", target_port);
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    bump_memlock_rlimit();

    obj = bpf_object__open_file("process_port_filter.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Get the PID of the target process
    pid_t target_pid = get_pid_by_name(proc_name);
    if (target_pid <= 0) {
        fprintf(stderr, "Could not find process '%s'\n", proc_name);
        return 1;
    }
    
    printf("Found process '%s' with PID: %d\n", proc_name, target_pid);

    // Manually populate the event map with our process info
    int eventmap_fd = bpf_object__find_map_fd_by_name(obj, "eventmap");
    if (eventmap_fd >= 0) {
        struct info event = {
            .pid = (__u32)target_pid,
            .lport = (__u16)target_port
        };
        strncpy(event.comm, proc_name, sizeof(event.comm) - 1);
        event.comm[sizeof(event.comm) - 1] = '\0';
        
        __u32 key = 0;
        if (bpf_map_update_elem(eventmap_fd, &key, &event, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set process info in event map\n");
            return 1;
        }
        printf("Set process info in event map\n");
    }

    // Manually populate the port-to-PID mapping
    int port_to_pid_fd = bpf_object__find_map_fd_by_name(obj, "port_to_pid");
    if (port_to_pid_fd >= 0) {
        __u16 port_key = (__u16)target_port;
        __u32 pid_value = (__u32)target_pid;
        if (bpf_map_update_elem(port_to_pid_fd, &port_key, &pid_value, BPF_ANY) < 0) {
            fprintf(stderr, "Failed to set port-to-PID mapping\n");
            return 1;
        }
        printf("Set port-to-PID mapping: port %d -> PID %d\n", target_port, target_pid);
    }

    // Attach XDP program
    struct bpf_program *xdp_prog = bpf_object__find_program_by_name(obj, "xdp_filter");
    if (!xdp_prog) {
        fprintf(stderr, "Could not find XDP program\n");
        return 1;
    }
    
    int ifindex = if_nametoindex("lo");
    if (ifindex == 0) {
        fprintf(stderr, "Interface lo not found\n");
        return 1;
    }
    
    struct bpf_link *xdp_link = bpf_program__attach_xdp(xdp_prog, ifindex);
    if (libbpf_get_error(xdp_link)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        return 1;
    }

    printf("XDP program attached to lo interface\n");
    printf("Monitoring traffic for process '%s' (PID: %d) on port %d\n", proc_name, target_pid, target_port);
    printf("Press Ctrl+C to stop.\n");
    
    // Main loop - show stats
    while (running) {
        // Show current event
        if (eventmap_fd >= 0) {
            __u32 key = 0;
            struct info event;
            int ret = bpf_map_lookup_elem(eventmap_fd, &key, &event);
            if (ret == 0) {
                printf("\n=== Current Process ===\n");
                printf("PID: %u\n", event.pid);
                printf("Process: %s\n", event.comm);
                printf("Port: %u\n", event.lport);
                printf("======================\n");
            }
        }
        
        // Show traffic statistics
        int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
        if (stats_fd >= 0) {
            printf("\n=== Traffic Statistics ===\n");
            printf("Port\tPID\tProcess\t\tPackets\n");
            printf("----\t---\t-------\t\t-------\n");
            
            __u32 key = 0, next_key;
            __u64 count;
            
            while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
                int ret = bpf_map_lookup_elem(stats_fd, &next_key, &count);
                if (ret == 0) {
                    // Decode the combined key: (port << 16) | pid
                    __u16 port = (next_key >> 16) & 0xFFFF;
                    __u32 pid = next_key & 0xFFFF;
                    
                    printf("%u\t%u\t%.12s\t\t%llu\n", port, pid, proc_name, count);
                }
                key = next_key;
            }
            printf("==========================\n");
        }
        
        sleep(2);
    }

    if (xdp_link) bpf_link__destroy(xdp_link);
    if (obj) bpf_object__close(obj);
    
    return 0;
}
