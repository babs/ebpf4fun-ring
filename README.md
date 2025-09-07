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
make clean && go generate && go build -o dns-capture . && sudo ./dns-capture ifName
```

## Usage

```bash
sudo ./dns-capture ifName
```

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
