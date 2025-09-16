#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

static int sockfd = -1;
static volatile int running = 1;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    running = 0;
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }
    exit(0);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in addr;
    int port = 8080;  // Default port
    
    // Parse command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Usage: %s [PORT]\n", argv[0]);
            printf("  PORT: Port number to bind to (default: 8080)\n");
            printf("  -h, --help: Show this help message\n");
            exit(0);
        }
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Error: Invalid port number. Port must be between 1 and 65535\n");
            fprintf(stderr, "Usage: %s [PORT]\n", argv[0]);
            exit(1);
        }
    }
    
    printf("Starting custom_server on port %d\n", port);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);   // Ctrl+C
    signal(SIGTERM, signal_handler);  // Termination signal
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }
    
    // Set up address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    // Bind socket
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        exit(1);
    }
    
    printf("custom_server bound to port %d\n", port);
    
    // Listen for connections
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        close(sockfd);
        exit(1);
    }
    
    printf("custom_server listening on port %d\n", port);
    printf("Press Ctrl+C to stop.\n");
    
    // Keep the process running until interrupted
    while (running) {
        sleep(1);
    }
    
    printf("custom_server shutting down...\n");
    if (sockfd >= 0) {
        close(sockfd);
    }
    return 0;
}