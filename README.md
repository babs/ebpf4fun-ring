# BPF Ring Buffer DNS Capture

eBPF tinkering.

## Installation

1. **Install system dependencies:**

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
```

then:

```bash
make clean && go generate && go build -o dns-capture . && sudo ./dns-capture
```

Or use the build script:

```bash
./build-run.sh
```

## Usage

```bash
# Monitor specific interface
sudo ./dns-capture eth0

# Monitor multiple specific interfaces
sudo ./dns-capture eth0 wlan0

# Monitor all interfaces (default)
sudo ./dns-capture

# Monitor interfaces matching a regex pattern
sudo ./dns-capture -pattern "eth.*|wlan.*"

# Monitor interfaces matching a pattern (no specific interfaces)
sudo ./dns-capture -pattern "enp.*"
```

### Command-line Options

- `-if-pattern string`: Regex pattern to filter interfaces (e.g., 'eth.*|wlan.*')
- `-domain-contains string`: Comma-separated list of strings to filter domains containing these substrings (e.g., 'google,facebook')
- `-verbose`: Enable verbose output with detailed DNS packet information

## Misc notes

### eBPF modes

- xdp: ingress only (commented)
- tc: ingress and egress

### Debug Mode

```c
bpf_printk("DNS packet captured: %d bytes\n", dns_len);
```

View kernel logs:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## License

This project is licensed under the GPL-2.0 License - see the eBPF program headers for details.
