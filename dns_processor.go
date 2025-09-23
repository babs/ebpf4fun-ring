package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	// Borrowed from https://github.com/cosanet/cosanet/blob/master/internal/controller_resolver/
	"ebpf4fun-ring/internal/controller_resolver"
)

// NewDNSProcessor creates a new DNS processor
func NewDNSProcessor(pattern *regexp.Regexp, domainFilters []string, verbose bool, podResolver controller_resolver.PodControllerResolver) (*DNSProcessor, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory limit: %v", err)
	}

	// // Load XDP eBPF program
	// xdpSpec, err := LoadDnsCaptureXDP()
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to load XDP eBPF spec: %v", err)
	// }
	// Load eBPF programs into kernel
	// xdpCollection, err := ebpf.NewCollection(xdpSpec)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create XDP eBPF collection: %v", err)
	// }
	// Create ring buffer reader for XDP
	// xdpReader, err := ringbuf.NewReader(xdpCollection.Maps["dns_events"])
	// if err != nil {
	// 	xdpCollection.Close()
	// 	return nil, fmt.Errorf("failed to create XDP ring buffer reader: %v", err)
	// }

	// Load TC eBPF program
	tcSpec, err := LoadDnsCaptureTC()
	if err != nil {
		return nil, fmt.Errorf("failed to load TC eBPF spec: %v", err)
	}

	tcCollection, err := ebpf.NewCollection(tcSpec)
	if err != nil {
		tcCollection.Close()
		return nil, fmt.Errorf("failed to create TC eBPF collection: %v", err)
	}

	// Create ring buffer reader for TC
	tcReader, err := ringbuf.NewReader(tcCollection.Maps["dns_events"])
	if err != nil {
		// xdpCollection.Close()
		tcCollection.Close()
		// xdpReader.Close()
		return nil, fmt.Errorf("failed to create TC ring buffer reader: %v", err)
	}

	// Calculate timestamp offset to convert eBPF boot-time to Unix time
	// eBPF uses bpf_ktime_get_ns() which is nanoseconds since boot
	// We need to convert this to nanoseconds since Unix epoch
	uptime, err := getSystemUptime()
	if err != nil {
		// xdpCollection.Close()
		tcCollection.Close()
		// xdpReader.Close()
		tcReader.Close()
		return nil, fmt.Errorf("failed to get system uptime: %v", err)
	}
	currentUnixNs := time.Now().UnixNano()
	bootTimeNs := currentUnixNs - uptime.Nanoseconds()
	timestampOffset := bootTimeNs

	return &DNSProcessor{
		//	xdpCollection:   xdpCollection,
		tcCollection: tcCollection,
		// xdpReader:       xdpReader,
		tcReader:         tcReader,
		timestampOffset:  timestampOffset,
		tcLinks:          make(map[string]link.Link),
		attachedIfaces:   make(map[string]bool),
		interfaceUpdates: make(chan string, 10),
		ifacePattern:     pattern,
		domainFilters:    domainFilters,
		verbose:          verbose,
		podResolver:      podResolver,
	}, nil
}

// AttachXDP attaches the XDP program to a network interface
func (dp *DNSProcessor) AttachXDP(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   dp.xdpCollection.Programs["dns_capture_xdp"],
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %v", err)
	}

	dp.xdpLink = xdpLink
	log.Printf("XDP program attached to interface %s", ifaceName)
	return nil
}

// AttachTC attaches the TC program to a network interface
func (dp *DNSProcessor) AttachTC(ifaceName string) error {
	if dp.attachedIfaces[ifaceName] {
		return nil // Already attached
	}

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	// Create qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Delete existing qdisc if it exists (ignore errors)
	netlink.QdiscDel(qdisc)

	// Add new qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add qdisc: %v", err)
	}

	// Create filter for TC egress
	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           dp.tcCollection.Programs["dns_capture_tc"].FD(),
		Name:         "dns_capture_tc_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		return fmt.Errorf("failed to attach TC egress program: %v", err)
	}

	// Create filter for TC ingress
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 2),
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           dp.tcCollection.Programs["dns_capture_tc"].FD(),
		Name:         "dns_capture_tc_ingress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return fmt.Errorf("failed to attach TC ingress program: %v", err)
	}

	dp.attachedIfaces[ifaceName] = true
	log.Printf("TC program attached to interface %s (both ingress and egress)", ifaceName)
	return nil
}

// MonitorInterfaces monitors for network interface changes and attaches/detaches eBPF programs accordingly
func (dp *DNSProcessor) MonitorInterfaces() {
	// Subscribe to netlink messages for interface changes
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(ch, done); err != nil {
		log.Printf("Failed to subscribe to link updates: %v", err)
		return
	}

	log.Println("Started monitoring for interface changes...")

	for update := range ch {
		iface := update.Link
		ifaceName := iface.Attrs().Name

		// Skip loopback interfaces
		if iface.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}

		switch update.Header.Type {
		case syscall.RTM_NEWLINK:
			// Interface added or changed
			if iface.Attrs().Flags&net.FlagUp != 0 && !dp.attachedIfaces[ifaceName] {
				// Check pattern filter if specified
				if dp.ifacePattern == nil || dp.ifacePattern.MatchString(ifaceName) {
					log.Printf("New interface detected: %s", ifaceName)
					if err := dp.AttachTC(ifaceName); err != nil {
						log.Printf("Failed to attach to new interface %s: %v", ifaceName, err)
					} else {
						log.Printf("Successfully attached to interface: %s", ifaceName)
					}
				}
			}
		case syscall.RTM_DELLINK:
			// Interface removed
			if dp.attachedIfaces[ifaceName] {
				log.Printf("Interface removed: %s", ifaceName)
				delete(dp.attachedIfaces, ifaceName)
				if link, exists := dp.tcLinks[ifaceName]; exists && link != nil {
					link.Close()
					delete(dp.tcLinks, ifaceName)
				}
			}
		}
	}
}

// ProcessEvents processes DNS events from the ring buffer
func (dp *DNSProcessor) ProcessEvents(ctx context.Context) error {
	log.Println("Starting DNS event processing...")

	dns_events := make(chan *ringbuf.Record)
	errors := make(chan error)

	// // Goroutine for XDP reader
	// go func() {
	// 	for {
	// 		record, err := dp.xdpReader.Read()
	// 		if err != nil {
	// 			if err == ringbuf.ErrClosed {
	// 				errors <- nil
	// 				return
	// 			}
	// 			errors <- fmt.Errorf("error reading from XDP ring buffer: %v", err)
	// 			continue
	// 		}
	// 		dns_events <- &record
	// 	}
	// }()

	// Goroutine for TC reader
	go func() {
		for {
			record, err := dp.tcReader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					errors <- nil
					return
				}
				errors <- fmt.Errorf("error reading from TC ring buffer: %v", err)
				continue
			}
			dns_events <- &record
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errors:
			if err != nil {
				log.Println(err)
			} else {
				return nil
			}
		case record := <-dns_events:
			dp.handleDNSEvent(record.RawSample)
		}
	}
}

// handleDNSEvent processes a single DNS event, now taking raw bytes to handle partial records
func (dp *DNSProcessor) handleDNSEvent(rawData []byte) {
	// Safely parse fields based on available data length
	var event DNSEvent
	dataLen := len(rawData)

	// Parse fixed-size fields at the beginning
	offset := 0
	if offset+1 <= dataLen {
		event.IPVersion = rawData[offset]
		offset++
	}
	if offset+1 <= dataLen {
		event.Protocol = rawData[offset]
		offset++
	}
	if offset+2 <= dataLen {
		event.SrcPort = binary.LittleEndian.Uint16(rawData[offset : offset+2])
		offset += 2
	}
	if offset+2 <= dataLen {
		event.DstPort = binary.LittleEndian.Uint16(rawData[offset : offset+2])
		offset += 2
	}
	if offset+2 <= dataLen {
		event.PacketLen = binary.LittleEndian.Uint16(rawData[offset : offset+2])
		offset += 2
	}
	if offset+8 <= dataLen {
		event.Timestamp = binary.LittleEndian.Uint64(rawData[offset : offset+8])
		offset += 8
	}
	if offset+4 <= dataLen {
		event.IfIndex = binary.LittleEndian.Uint32(rawData[offset : offset+4])
		offset += 4
	}
	if offset+32 <= dataLen {
		copy(event.Addr[:], rawData[offset:offset+32])
		offset += 32
	}
	// DNS data is the rest, up to MaxDnsPacketSize
	if offset < dataLen {
		copyLen := dataLen - offset
		if copyLen > MaxDnsPacketSize {
			copyLen = MaxDnsPacketSize
		}
		copy(event.DNSData[:copyLen], rawData[offset:offset+copyLen])
		// If packetLen indicates more data than available, adjust
		if int(event.PacketLen) > copyLen {
			event.PacketLen = uint16(copyLen)
		}
	}

	// Now proceed with the rest of the function, using the parsed event
	var srcIP, dstIP string

	// Handle IPv4 vs IPv6
	if event.IPVersion == 4 {
		// IPv4: first 4 bytes are src, next 4 bytes are dst
		srcIP = intToIP(binary.LittleEndian.Uint32(event.Addr[0:4])).String()
		dstIP = intToIP(binary.LittleEndian.Uint32(event.Addr[4:8])).String()
	} else if event.IPVersion == 6 {
		// IPv6: first 16 bytes are src, next 16 bytes are dst
		srcIP = net.IP(event.Addr[0:16]).String()
		dstIP = net.IP(event.Addr[16:32]).String()
	} else {
		srcIP = "unknown"
		dstIP = "unknown"
	}

	protocol := "UDP"
	if event.Protocol == ProtocolTCP {
		protocol = "TCP"
	}

	timestamp := time.Unix(0, int64(event.Timestamp+uint64(dp.timestampOffset)))

	if dataLen < int(unsafe.Sizeof(DNSEvent{})) {
		fmt.Printf(" [PARTIAL RECORD: %d/%d bytes]", dataLen, int(unsafe.Sizeof(DNSEvent{})))
	}

	if event.PacketLen > 0 && event.PacketLen <= MaxDnsPacketSize {
		dnsData := event.DNSData[:event.PacketLen]
		dp.parseDNSPacket(dnsData, &event, srcIP, dstIP)
	} else {
		// Only log oversized packets
		fmt.Printf("[%s] IPv%d %s %s:%d -> %s:%d (%d bytes) - OVERSIZED PACKET\n",
			timestamp.Format("2006-01-02 15:04:05.000"),
			event.IPVersion,
			protocol,
			srcIP, event.SrcPort,
			dstIP, event.DstPort,
			event.PacketLen)
	}
}

// parseDNSPacket attempts to parse basic DNS packet information
func (dp *DNSProcessor) parseDNSPacket(data []byte, event *DNSEvent, srcIP, dstIP string) {
	if len(data) < 12 {
		fmt.Println("DNS packet too short")
		return
	}

	// Use miekg/dns to parse the DNS packet
	msg := new(dns.Msg)
	err := msg.Unpack(data)
	if err != nil {
		fmt.Printf("Error parsing DNS packet with miekg/dns: %v\n", err)
		// Fallback to basic header parsing
		dp.parseDNSHeaderFallback(data)
		return
	}

	// Apply domain filtering if filters are specified
	if len(dp.domainFilters) > 0 {
		matches := false
		for _, q := range msg.Question {
			domain := strings.ToLower(q.Name)
			for _, filter := range dp.domainFilters {
				if strings.Contains(domain, strings.ToLower(filter)) {
					matches = true
					break
				}
			}
			if matches {
				break
			}
		}
		if !matches {
			// No domains match the filters, skip this packet
			return
		}
	}

	// Add log here
	var srcPodName, dstPodName, srcPodNamespace, dstPodNamespace string
	if dp.podResolver != nil {
		if pod, ok := dp.podResolver.GetPodByIP(srcIP); ok {
			srcPodName = pod.Name
			srcPodNamespace = pod.Namespace
		}
		if pod, ok := dp.podResolver.GetPodByIP(dstIP); ok {
			dstPodName = pod.Name
			dstPodNamespace = pod.Namespace
		}
	}

	// Resolve interface name from index
	var ifaceName string
	if event.IfIndex > 0 {
		if iface, err := net.InterfaceByIndex(int(event.IfIndex)); err == nil {
			ifaceName = iface.Name
		}
	}

	var questions []string
	for _, q := range msg.Question {
		questions = append(questions, fmt.Sprintf("%s %s", q.Name, dns.TypeToString[q.Qtype]))
	}
	questionStr := strings.Join(questions, "; ")

	logger.Info("DNS packet",
		zap.String("source_ip", srcIP),
		zap.String("dest_ip", dstIP),
		zap.Uint16("source_port", event.SrcPort),
		zap.Uint16("dest_port", event.DstPort),
		zap.Bool("is_response", msg.Response),
		zap.Uint16("dns_id", msg.Id),
		zap.String("questions", questionStr),
		zap.String("interface", ifaceName),
		zap.String("src_pod_name", srcPodName),
		zap.String("src_pod_namespace", srcPodNamespace),
		zap.String("dst_pod_name", dstPodName),
		zap.String("dst_pod_namespace", dstPodNamespace),
	)

	// Display basic DNS information
	if dp.verbose {
		fmt.Printf("  DNS ID: %d, Type: %s, Opcode: %s, RCode: %s\n",
			msg.Id,
			map[bool]string{true: "Response", false: "Query"}[msg.Response],
			dns.OpcodeToString[msg.Opcode],
			dns.RcodeToString[msg.Rcode])

		fmt.Printf("  Questions: %d, Answers: %d, Authority: %d, Additional: %d\n",
			len(msg.Question), len(msg.Answer), len(msg.Ns), len(msg.Extra))

		// Display questions
		if len(msg.Question) > 0 {
			var queries []string
			for _, q := range msg.Question {
				queries = append(queries, fmt.Sprintf("%s (%s)", q.Name, dns.TypeToString[q.Qtype]))
			}
			fmt.Printf("  Queries: %s\n", strings.Join(queries, ", "))
		}

		// Display answers
		if msg.Response && len(msg.Answer) > 0 {
			var answers []string
			for _, rr := range msg.Answer {
				answers = append(answers, rr.String())
			}
			fmt.Printf("  Answers: %s\n", strings.Join(answers, ", "))
		}

		// Display authority records
		if msg.Response && len(msg.Ns) > 0 {
			var authorities []string
			for _, rr := range msg.Ns {
				authorities = append(authorities, rr.String())
			}
			fmt.Printf("  Authority: %s\n", strings.Join(authorities, ", "))
		}

		// Display additional records
		if len(msg.Extra) > 0 {
			var additional []string
			for _, rr := range msg.Extra {
				additional = append(additional, rr.String())
			}
			fmt.Printf("  Additional: %s\n", strings.Join(additional, ", "))
		}

		// Show hex dump of all captured data (limited)
		hexDump := make([]string, 0)
		dumpSize := len(data)
		dumpstep := 32
		maxdumpsize := 256
		if dumpSize > maxdumpsize {
			dumpSize = maxdumpsize
		}
		for i := 0; i < dumpSize; i += dumpstep {
			end := i + dumpstep
			if end > dumpSize {
				end = dumpSize
			}
			hexDump = append(hexDump, fmt.Sprintf("  %04x: % x", i, data[i:end]))
		}
		fmt.Println("  Hex dump:")
		for _, line := range hexDump {
			fmt.Println(line)
		}
		if len(data) > maxdumpsize {
			fmt.Printf("  ... (%d more bytes)\n", len(data)-maxdumpsize)
		}
	}
}

// parseDNSHeaderFallback provides basic header parsing when miekg/dns fails
func (dp *DNSProcessor) parseDNSHeaderFallback(data []byte) {
	if len(data) < 12 {
		fmt.Println("DNS packet too short for fallback parsing")
		return
	}

	reader := bytes.NewReader(data)
	var header struct {
		ID      uint16
		Flags   uint16
		QDCount uint16
		ANCount uint16
		NSCount uint16
		ARCount uint16
	}

	fields := []*uint16{&header.ID, &header.Flags, &header.QDCount, &header.ANCount, &header.NSCount, &header.ARCount}
	fieldNames := []string{"ID", "Flags", "QDCount", "ANCount", "NSCount", "ARCount"}

	for i, field := range fields {
		if err := binary.Read(reader, binary.BigEndian, field); err != nil {
			fmt.Printf("unable to properly read header (%s): %v\n", fieldNames[i], err)
		}
	}

	isResponse := (header.Flags & 0x8000) != 0
	opcode := (header.Flags >> 11) & 0x0F
	rcode := header.Flags & 0x0F

	fmt.Printf("  DNS ID: %d, Type: %s, Opcode: %d, RCode: %d (fallback parsing)\n",
		header.ID,
		map[bool]string{true: "Response", false: "Query"}[isResponse],
		opcode,
		rcode)

	fmt.Printf("  Questions: %d, Answers: %d, Authority: %d, Additional: %d\n",
		header.QDCount, header.ANCount, header.NSCount, header.ARCount)

	// Show limited hex dump
	dumpSize := len(data)
	if dumpSize > 128 {
		dumpSize = 128
	}
	fmt.Printf("  Hex dump (first %d bytes):\n", dumpSize)
	for i := 0; i < dumpSize; i += 16 {
		end := i + 16
		if end > dumpSize {
			end = dumpSize
		}
		fmt.Printf("  %04x: % x\n", i, data[i:end])
	}
	if len(data) > dumpSize {
		fmt.Printf("  ... (%d more bytes)\n", len(data)-dumpSize)
	}
}

// Close cleans up resources
func (dp *DNSProcessor) Close() {
	if dp.xdpReader != nil {
		dp.xdpReader.Close()
	}
	if dp.tcReader != nil {
		dp.tcReader.Close()
	}
	if dp.xdpLink != nil {
		dp.xdpLink.Close()
	}
	// Close all TC links
	for ifaceName := range dp.attachedIfaces {
		if link, exists := dp.tcLinks[ifaceName]; exists && link != nil {
			link.Close()
		}
		// Remove clsact qdisc
		if iface, err := netlink.LinkByName(ifaceName); err == nil {
			qdisc := &netlink.GenericQdisc{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: iface.Attrs().Index,
					Handle:    netlink.MakeHandle(0xffff, 0),
					Parent:    netlink.HANDLE_CLSACT,
				},
				QdiscType: "clsact",
			}
			_ = netlink.QdiscDel(qdisc) // ignore error
		}
	}
	if dp.xdpCollection != nil {
		dp.xdpCollection.Close()
	}
	if dp.tcCollection != nil {
		dp.tcCollection.Close()
	}
}
