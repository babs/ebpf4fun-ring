package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" DnsCaptureXDP ebpf/dns_capture_xdp.c -- -I/usr/include/ -I /usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" DnsCaptureTC ebpf/dns_capture_tc.c -- -I/usr/include/ -I /usr/include/x86_64-linux-gnu

const (
	MaxDnsPacketSize = 1496
	// MaxDnsPacketSize = 4996
	ProtocolUDP = 17
	ProtocolTCP = 6
)

// DNSHeader represents DNS header structure
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSEvent represents the structure of events from the BPF program
// This must match the C struct exactly (packed layout)
type DNSEvent struct {
	IPVersion uint8                  // offset 0
	Protocol  uint8                  // offset 1
	SrcPort   uint16                 // offset 2
	DstPort   uint16                 // offset 4
	PacketLen uint16                 // offset 6
	Timestamp uint64                 // offset 8
	Addr      [32]byte               // offset 16 (union as raw bytes)
	DNSData   [MaxDnsPacketSize]byte // offset 48
}

// DNSProcessor handles DNS packet processing
type DNSProcessor struct {
	xdpCollection   *ebpf.Collection
	tcCollection    *ebpf.Collection
	xdpReader       *ringbuf.Reader
	tcReader        *ringbuf.Reader
	xdpLink         link.Link
	tcLink          link.Link
	timestampOffset int64  // Offset to convert eBPF boot-time to Unix time
	tcIfaceName     string // Store the interface name for TC qdisc cleanup
}

// getSystemUptime reads the system uptime from /proc/uptime
func getSystemUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	// Parse the first field (uptime in seconds)
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid uptime format")
	}

	uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return time.Duration(uptimeSeconds * float64(time.Second)), nil
}

// intToIP converts a uint32 to net.IP
func intToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: ./dns-capture <interface_name>")
	}

	ifaceName := os.Args[1]

	// Create DNS processor
	processor, err := NewDNSProcessor()
	if err != nil {
		log.Fatalf("Failed to create DNS processor: %v", err)
	}
	defer processor.Close()

	// if err := processor.AttachXDP(ifaceName); err != nil {
	// 	log.Fatalf("Failed to attach TC program: %v", err)
	// }

	if err := processor.AttachTC(ifaceName); err != nil {
		log.Fatalf("Failed to attach TC program: %v", err)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	// Start processing events
	fmt.Printf("Capturing DNS traffic on interface %s...\n", ifaceName)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 80))

	if err := processor.ProcessEvents(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Error processing events: %v", err)
	}

	log.Println("DNS capture stopped")
}
