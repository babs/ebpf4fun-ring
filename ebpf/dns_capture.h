#ifndef __DNS_CAPTURE_H__
#define __DNS_CAPTURE_H__

#include <linux/types.h>

// #define MAX_DNS_PACKET_SIZE 5000
#define MAX_DNS_PACKET_SIZE 1500
#define DNS_PORT 53

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// Event structure for DNS packets (supports both IPv4 and IPv6)
struct dns_event {
    __u8 ip_version;  // 4 for IPv4, 6 for IPv6
    __u8 protocol;    // 6 for TCP, 17 for UDP
    __u16 src_port;
    __u16 dst_port;
    __u16 packet_len;
    __u64 timestamp;
    __u32 ifindex;    // Interface index
    union {
        struct {
            __u32 src_ip;
            __u32 dst_ip;
            __u8 padding[24]; // Pad to IPv6 size
        } ipv4;
        struct {
            __u8 src_ip[16];
            __u8 dst_ip[16];
        } ipv6;
    } addr;
    __u8 dns_data[MAX_DNS_PACKET_SIZE];
} __attribute__((packed));

#endif /* __DNS_CAPTURE_H__ */
