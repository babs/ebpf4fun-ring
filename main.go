package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	// Borrowed from https://github.com/cosanet/cosanet/blob/master/internal/controller_resolver/
	"ebpf4fun-ring/internal/controller_resolver"
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
	xdpCollection    *ebpf.Collection
	tcCollection     *ebpf.Collection
	xdpReader        *ringbuf.Reader
	tcReader         *ringbuf.Reader
	xdpLink          link.Link
	tcLinks          map[string]link.Link // Map of interface name to TC link
	timestampOffset  int64                // Offset to convert eBPF boot-time to Unix time
	attachedIfaces   map[string]bool      // Track attached interfaces
	interfaceUpdates chan string          // Channel for interface updates
	ifacePattern     *regexp.Regexp       // Regex pattern for interface filtering
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
	var ifacePattern = flag.String("pattern", "", "Regex pattern to filter interfaces (e.g., 'eth.*|wlan.*')")
	flag.Parse()

	var ifaceNames []string
	var pattern *regexp.Regexp
	var err error

	// Compile regex pattern if provided
	if *ifacePattern != "" {
		pattern, err = regexp.Compile(*ifacePattern)
		if err != nil {
			log.Fatalf("Invalid regex pattern: %v", err)
		}
	}

	// Check for positional interface arguments
	args := flag.Args()
	if len(args) > 0 {
		// Specific interfaces provided
		ifaceNames = args
	} else {
		// No interface specified, get all interfaces (optionally filtered by pattern)
		interfaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Failed to get network interfaces: %v", err)
		}

		for _, iface := range interfaces {
			// Skip loopback and down interfaces
			if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
				// Apply pattern filter if specified
				if pattern == nil || pattern.MatchString(iface.Name) {
					ifaceNames = append(ifaceNames, iface.Name)
				}
			}
		}

		if len(ifaceNames) == 0 {
			if pattern != nil {
				log.Fatalf("No interfaces found matching pattern '%s'", *ifacePattern)
			} else {
				log.Fatal("No suitable network interfaces found")
			}
		}

		if pattern != nil {
			log.Printf("Monitoring interfaces matching pattern '%s': %v", *ifacePattern, ifaceNames)
		} else {
			log.Printf("No interface specified, monitoring all interfaces: %v", ifaceNames)
		}
	}

	// Controller resolver (borrowed from cosanet)
	nodename := os.Getenv("NODE_NAME")
	if nodename == "" {
		var err error
		nodename, err = os.Hostname()
		if err != nil {
			slog.Error("Failed to get hostname", slog.Any("err", err))
		}
	}

	// To be used later for data consolidation
	_ = controller_resolver.NewResolver(
		&controller_resolver.ResolverOptions{
			Nodename: nodename,
		},
	)

	// Create DNS processor
	processor, err := NewDNSProcessor(pattern)
	if err != nil {
		log.Fatalf("Failed to create DNS processor: %v", err)
	}
	defer processor.Close()

	// Attach to all specified interfaces
	for _, ifaceName := range ifaceNames {
		if err := processor.AttachTC(ifaceName); err != nil {
			log.Printf("Failed to attach to interface %s: %v", ifaceName, err)
			continue
		}
		log.Printf("Attached to interface: %s", ifaceName)
	}

	// Start interface monitoring for hot additions
	go processor.MonitorInterfaces()

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
	fmt.Printf("Capturing DNS traffic on interfaces: %v\n", ifaceNames)
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println(strings.Repeat("=", 80))

	if err := processor.ProcessEvents(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Error processing events: %v", err)
	}

	log.Println("DNS capture stopped")
}
