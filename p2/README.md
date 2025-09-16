# Process Port Filter - BPF Traffic Monitor

A BPF (Berkeley Packet Filter) program that monitors network traffic for specific processes bound to specific ports. This tool uses XDP (eXpress Data Path) to capture and correlate network packets with running processes in real-time.

## Features

- **Process-Specific Monitoring**: Monitor traffic for a specific process by name
- **Port-Based Filtering**: Track traffic on specific ports
- **Real-time Statistics**: Live updates showing packet counts per process/port
- **PID Correlation**: Links network traffic to specific process IDs
- **XDP Performance**: High-performance packet processing using XDP

## Requirements

- Linux kernel with BPF/XDP support
- `clang` and `llvm-strip` for BPF compilation
- `libbpf` development libraries
- Root privileges for BPF program loading

### Install Dependencies (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Building

```bash
# Build BPF program and loader
make clean && make all
```

## Usage

### Basic Usage
```bash

# Monitor custom process and port
sudo ./loader <process_name> <port>

# Example
sudo ./loader myprocess 8080
```

### Command Line Arguments
- **Process Name**: Name of the process to monitor (default: "myprocess")
- **Port**: Port number to monitor (default: 5050)

## Testing

```bash
# Terminal 1: Start the test process
./custom_server 5050 &

# Terminal 2: Start the monitor
sudo ./loader custom_server 5050

# Terminal 3: Send test data
echo "Hello from client" | nc localhost 5050
```

## How It Works

1. **BPF Program** (`process_port_filter.bpf.c`):
   - **Kprobe**: Intercepts socket bind operations to track which process binds to which port
   - **XDP Program**: Captures incoming network packets and correlates them with bound processes
   - **Maps**: Store process information and traffic statistics

2. **User-Space Loader** (`loader.c`):
   - Finds the target process by name using `pgrep`
   - Populates BPF maps with process information
   - Attaches XDP program to network interface
   - Reads and displays statistics from BPF maps

### Key Components

#### BPF Maps
- **`eventmap`**: Stores current process binding events
- **`port_to_pid`**: Maps ports to process IDs
- **`stats`**: Tracks packet counts by port and PID

#### Process Detection
- Uses `pgrep -x <process_name>` to find the target process
- Manually populates BPF maps with process information
- Correlates network traffic with specific processes

#### Traffic Monitoring
- XDP program captures packets on the loopback interface
- Filters packets by destination port
- Increments statistics for matching port/PID combinations

## Troubleshooting

### Common Issues I had to face

1. **"Could not find process"**
   - Ensure the process is running: `ps aux | grep <process_name>`
   - Process must be bound to a port

2. **"Failed to attach XDP program"**
   - Check if interface exists: `ip link show lo`
   - Verify BPF program compiled successfully

3. **No traffic statistics**
   - Check if packets are going to the monitored port
   - Verify XDP program is attached: `ip link show lo`
