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
	"go.uber.org/zap"

	// Borrowed from https://github.com/cosanet/cosanet/blob/master/internal/controller_resolver/
	"ebpf4fun-ring/internal/controller_resolver"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" DnsCaptureXDP ebpf/dns_capture_xdp.c -- -I/usr/include/ -I /usr/include/x86_64-linux-gnu
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" DnsCaptureTC ebpf/dns_capture_tc.c -- -I/usr/include/ -I /usr/include/x86_64-linux-gnu

const (
	// MaxDnsPacketSize = 1496
	MaxDnsPacketSize = 1500
	// MaxDnsPacketSize = 4996
	ProtocolUDP = 17
	ProtocolTCP = 6
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "1970-01-01T00:00:00"
	Builder        = "go version go1.xx.y os/platform"
	ProjectURL     = "https://github.com/babs/ebpf4fun-ring"
)

// cliOpts holds command-line options
type cliOpts struct {
	ifacePattern   string
	domainContains string
	verbose        bool
	logDev         bool
	logStacktraces bool
	logLevel       string
}

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
	IfIndex   uint32                 // offset 16
	Addr      [32]byte               // offset 20 (union as raw bytes)
	DNSData   [MaxDnsPacketSize]byte // offset 52
}

// DNSProcessor handles DNS packet processing
type DNSProcessor struct {
	xdpCollection    *ebpf.Collection
	tcCollection     *ebpf.Collection
	xdpReader        *ringbuf.Reader
	tcReader         *ringbuf.Reader
	xdpLink          link.Link
	tcLinks          map[string]link.Link                      // Map of interface name to TC link
	timestampOffset  int64                                     // Offset to convert eBPF boot-time to Unix time
	attachedIfaces   map[string]bool                           // Track attached interfaces
	interfaceUpdates chan string                               // Channel for interface updates
	ifacePattern     *regexp.Regexp                            // Regex pattern for interface filtering
	domainFilters    []string                                  // List of strings to filter domains containing these substrings
	verbose          bool                                      // Enable verbose output
	podResolver      controller_resolver.PodControllerResolver // Pod resolver for IP to pod mapping
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

var logger *zap.Logger

func main() {
	var opts cliOpts
	flag.StringVar(&opts.ifacePattern, "if-pattern", "", "Regex pattern to filter interfaces (e.g., 'eth.*|wlan.*')")
	flag.StringVar(&opts.domainContains, "domain-contains", "", "Comma-separated list of strings to filter domains containing these substrings (e.g., 'google,facebook')")
	flag.BoolVar(&opts.verbose, "verbose", false, "Enable verbose output with detailed DNS packet information")
	flag.BoolVar(&opts.logDev, "log-dev", false, "Enable development logging mode")
	flag.BoolVar(&opts.logStacktraces, "log-stacktraces", false, "Include stacktraces in logs")
	flag.StringVar(&opts.logLevel, "log-level", "info", "Set log level (debug, info, warn, error)")
	flag.Parse()
	args := flag.Args()

	initLog(&opts)
	defer logger.Sync()

	var domainFilters []string
	if opts.domainContains != "" {
		domainFilters = strings.Split(opts.domainContains, ",")
		// Trim spaces from each filter
		for i, filter := range domainFilters {
			domainFilters[i] = strings.TrimSpace(filter)
		}
	}

	logger.Info("Build Info",
		zap.String("version", Version),
		zap.String("commit_hash", CommitHash),
		zap.String("build_timestamp", BuildTimestamp),
		zap.String("builder", Builder),
		zap.String("project_url", ProjectURL),
	)
	logger.Info("Starting",
		zap.String("iface_pattern", opts.ifacePattern),
		zap.String("domain_contains", opts.domainContains),
		zap.Bool("verbose", opts.verbose),
		zap.Bool("log_dev", opts.logDev),
		zap.Bool("log_stacktraces", opts.logStacktraces),
		zap.String("log_level", opts.logLevel),
		zap.Strings("interfaces", args),
	)

	var ifaceNames []string
	var pattern *regexp.Regexp
	var err error

	// Compile regex pattern if provided
	if opts.ifacePattern != "" {
		pattern, err = regexp.Compile(opts.ifacePattern)
		if err != nil {
			log.Fatalf("Invalid regex pattern: %v", err)
		}
	}

	// Check for positional interface arguments
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
				log.Fatalf("No interfaces found matching pattern '%s'", opts.ifacePattern)
			} else {
				log.Fatal("No suitable network interfaces found")
			}
		}

		if pattern != nil {
			log.Printf("Monitoring interfaces matching pattern '%s': %v", opts.ifacePattern, ifaceNames)
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
	podResolver := controller_resolver.NewResolver(
		&controller_resolver.ResolverOptions{
			Nodename: nodename,
		},
	)

	// Create DNS processor
	processor, err := NewDNSProcessor(pattern, domainFilters, opts.verbose, podResolver)
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
