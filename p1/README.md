# eBPF TCP Packet Dropper

This project implements an eBPF XDP program that drops TCP packets on a configurable port. The port number can be configured from userspace using BPF maps, making it dynamic and flexible.

## Features

- **XDP-based packet filtering**: High-performance packet processing at the kernel level
- **Configurable port**: Port number can be set dynamically from userspace
- **TCP protocol filtering**: Specifically targets TCP packets
- **Real-time statistics**: Tracks dropped packets and provides statistics
- **Safe operation**: Includes bounds checking and error handling

## Architecture


### BPF Maps

- `blocked_ports`: Hash map storing port numbers to block (key: port, value: 1)
- `stats`: Hash map storing statistics (key: port, value: drop count)

## Requirements

- Linux kernel 4.18+ (for XDP support)
- clang/LLVM 10+
- libbpf development libraries
- Root privileges for loading eBPF programs

## Building

```bash
make all
```

This will compile both the eBPF program (`xdp_drop_port.o`) and the userspace loader (`loader`).

## Usage


### Command Line Options

- `-i, --interface`: Network interface to attach to (default: lo)
- `-p, --port`: Port number(s) to block (comma-separated for multiple ports)
- `-s, --stats`: Show statistics
- `-u, --unload`: Unload the eBPF program
- `-h, --help`: Show help message

### Testing

```bash
# Terminal 1: Start the eBPF program
sudo ./loader -i lo -p 4040

# Terminal 2: Test with netcat
nc -l 4040 &
nc localhost 4040  # Should fail - connection refused

# Terminal 3: Check statistics
sudo ./loader -s

# Terminal 4: Unload when done
sudo ./loader -u
```


## Cleanup

Use Ctrl+C to stop the program

## Troubleshooting

### Common Issues

1. **Permission denied**: Run with sudo
2. **Interface not found**: Check interface name with `ip link show`
3. **eBPF program load failed**: Ensure kernel supports XDP and BPF
4. **No packets dropped**: Verify the port is actually being used
