// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "dns_capture.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB max
} dns_events SEC(".maps");

SEC("tc")
int dns_capture_tc(struct __sk_buff *skb) {
    __u8 *data = (__u8 *)(long)skb->data;
    __u8 *data_end = (__u8 *)(long)skb->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    __u8 *cursor = data + sizeof(*eth);
    __u8 ip_version = 0;
    __u8 protocol = 0;
    __u16 src_port = 0, dst_port = 0;
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;

    if (eth_proto == ETH_P_IP) {
        iph = (struct iphdr *)cursor;
        if (cursor + sizeof(*iph) > data_end)
            return TC_ACT_OK;
        ip_version = 4;
        protocol = iph->protocol;
        cursor += iph->ihl * 4;
        if (cursor > data_end)
            return TC_ACT_OK;
        if (protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)cursor;
            if (cursor + sizeof(*udph) > data_end)
                return TC_ACT_OK;
            src_port = bpf_ntohs(udph->source);
            dst_port = bpf_ntohs(udph->dest);
            cursor = (__u8 *)udph + sizeof(*udph);
            if (cursor > data_end)
                return TC_ACT_OK;
        } else if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)cursor;
            if (cursor + sizeof(*tcph) > data_end)
                return TC_ACT_OK;
            src_port = bpf_ntohs(tcph->source);
            dst_port = bpf_ntohs(tcph->dest);
            cursor = (__u8 *)tcph + sizeof(*tcph);
            if (cursor > data_end)
                return TC_ACT_OK;
        } else {
            return TC_ACT_OK;
        }
    } else if (eth_proto == ETH_P_IPV6) {
        ip6h = (struct ipv6hdr *)cursor;
        if (cursor + sizeof(*ip6h) > data_end)
            return TC_ACT_OK;
        ip_version = 6;
        protocol = ip6h->nexthdr;
        cursor += sizeof(*ip6h);
        if (cursor > data_end)
            return TC_ACT_OK;
        if (protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)cursor;
            if (cursor + sizeof(*udph) > data_end)
                return TC_ACT_OK;
            src_port = bpf_ntohs(udph->source);
            dst_port = bpf_ntohs(udph->dest);
            cursor = (__u8 *)udph + sizeof(*udph);
            if (cursor > data_end)
                return TC_ACT_OK;
        } else if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)cursor;
            if (cursor + sizeof(*tcph) > data_end)
                return TC_ACT_OK;
            src_port = bpf_ntohs(tcph->source);
            dst_port = bpf_ntohs(tcph->dest);
            cursor = (__u8 *)tcph + sizeof(*tcph);
            if (cursor > data_end)
                return TC_ACT_OK;
        } else {
            return TC_ACT_OK;
        }
    } else {
        return TC_ACT_OK;
    }

    // Check for DNS port (53)
    if (src_port != 53 && dst_port != 53)
        return TC_ACT_OK;

    // Calculate DNS payload length safely
    __u64 len = data_end - cursor;
    if (len == 0)
        return TC_ACT_OK;
    if (len > MAX_DNS_PACKET_SIZE)
        len = MAX_DNS_PACKET_SIZE;
    __u32 dns_payload_len = (__u32)len;

    // Reserve ringbuf space
    struct dns_event *event = bpf_ringbuf_reserve(&dns_events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;

    __u64 timestamp = bpf_ktime_get_ns();
    event->timestamp = timestamp;
    event->ip_version = ip_version;
    event->protocol = protocol;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->packet_len = dns_payload_len;

    if (ip_version == 4 && iph) {
        event->addr.ipv4.src_ip = iph->saddr;
        event->addr.ipv4.dst_ip = iph->daddr;
    } else if (ip_version == 6 && ip6h) {
        __builtin_memcpy(event->addr.ipv6.src_ip, &ip6h->saddr, 16);
        __builtin_memcpy(event->addr.ipv6.dst_ip, &ip6h->daddr, 16);
    }

    // bpf_printk("src: %d\tdst: %d\tpayload len: %d\n",src_port, dst_port, data_end - cursor);
    if (bpf_probe_read_kernel(event->dns_data, dns_payload_len, (void *)cursor) < 0) {
        bpf_ringbuf_discard(event, 0);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(event, 0);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
