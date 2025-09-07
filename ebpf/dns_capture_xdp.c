// go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns_capture.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16MB ring buffer
} dns_events SEC(".maps");

SEC("xdp")
int dns_capture_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct udphdr *udp = NULL;
    struct tcphdr *tcp = NULL;
    struct dns_event *event = NULL;
    __u8 ip_version = 0;
    __u8 transport_proto = 0;
    void *ip_header = NULL;  // Will point to either IPv4 or IPv6 header

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        transport_proto = ip->protocol;
        if (transport_proto != IPPROTO_UDP && transport_proto != IPPROTO_TCP)
            return XDP_PASS;

        if (transport_proto == IPPROTO_UDP) {
            udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
        } else {
            tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
        }

        ip_version = 4;
        ip_header = ip;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_PASS;

        transport_proto = ipv6->nexthdr;
        if (transport_proto != IPPROTO_UDP && transport_proto != IPPROTO_TCP)
            return XDP_PASS;

        if (transport_proto == IPPROTO_UDP) {
            udp = (void *)(ipv6 + 1);
            if ((void *)(udp + 1) > data_end)
                return XDP_PASS;
        } else {
            tcp = (void *)(ipv6 + 1);
            if ((void *)(tcp + 1) > data_end)
                return XDP_PASS;
        }

        ip_version = 6;
        ip_header = ipv6;
    } else {
        return XDP_PASS;
    }

    // Common processing for both IPv4 and IPv6
    // Check for DNS port
    if (transport_proto == IPPROTO_UDP) {
        if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
            return XDP_PASS;
    } else {
        // bpf_printk("TCP packet: src_port=%u, dest_port=%u", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        if (tcp->dest != bpf_htons(53) && tcp->source != bpf_htons(53))
            return XDP_PASS;
    }

    // Reserve space for event
    event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;

    // Fill basic event info
    event->timestamp = bpf_ktime_get_ns();
    event->ip_version = ip_version;
    event->protocol = transport_proto;
    event->src_port = transport_proto == IPPROTO_UDP ? bpf_ntohs(udp->source) : bpf_ntohs(tcp->source);
    event->dst_port = transport_proto == IPPROTO_UDP ? bpf_ntohs(udp->dest) : bpf_ntohs(tcp->dest);

    // Fill IP-specific address info
    if (ip_version == 4) {
        struct iphdr *ip = (struct iphdr *)ip_header;
        event->addr.ipv4.src_ip = ip->saddr;
        event->addr.ipv4.dst_ip = ip->daddr;
    } else {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)ip_header;
        __builtin_memcpy(event->addr.ipv6.src_ip, ipv6->saddr.in6_u.u6_addr8, 16);
        __builtin_memcpy(event->addr.ipv6.dst_ip, ipv6->daddr.in6_u.u6_addr8, 16);
    }

    // Copy DNS data efficiently - focus on getting the start of the packet
    void *dns_data;
    __u32 copy_len;

    if (transport_proto == IPPROTO_UDP) {
        dns_data = (void *)(udp + 1);
        __u32 udp_offset = (__u32)((char *)udp - (char *)data);
        __u32 dns_offset = udp_offset + sizeof(struct udphdr);
        __u32 data_len = (__u32)((char *)data_end - (char *)data);
        __u32 avail_len = data_len > dns_offset ? data_len - dns_offset : 0;
        copy_len = avail_len > MAX_DNS_PACKET_SIZE ? MAX_DNS_PACKET_SIZE : avail_len;
    } else {
        // TCP
        __u32 tcp_hdr_len = tcp->doff * 4;
        void *tcp_payload = (void *)tcp + tcp_hdr_len;
        if ((void *)tcp_payload + 2 > data_end) {
            bpf_ringbuf_discard(event, 0);
            return XDP_PASS; // need at least 2 bytes for length
        }
        __u16 dns_len_be;
        bpf_probe_read_kernel(&dns_len_be, 2, tcp_payload);
        __u16 dns_len = bpf_ntohs(dns_len_be);
        dns_data = tcp_payload + 2;
        __u32 tcp_offset = (__u32)((char *)tcp - (char *)data);
        __u32 dns_offset = tcp_offset + tcp_hdr_len + 2;
        __u32 data_len = (__u32)((char *)data_end - (char *)data);
        __u32 avail_len = data_len > dns_offset ? data_len - dns_offset : 0;
        copy_len = avail_len > dns_len ? dns_len : avail_len;
        copy_len = copy_len > MAX_DNS_PACKET_SIZE ? MAX_DNS_PACKET_SIZE : copy_len;
    }

    event->packet_len = copy_len;

    // Use bpf_probe_read_kernel to safely copy the DNS payload
    if (copy_len > 0) {
        bpf_probe_read_kernel(event->dns_data, copy_len, dns_data);
    }
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}
