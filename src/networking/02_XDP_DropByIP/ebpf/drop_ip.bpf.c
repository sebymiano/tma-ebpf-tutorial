#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bpf_log.h"

#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

/* TODO 5: Define map for IP dst blocklist */

struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1024);
} blocklist_dst SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   /* TODO 1: Fix bound checking errors */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

/* TODO 3: Implement IP parsing function */
// static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
// }

SEC("xdp")
int xdp_drop_by_ip(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   int eth_type;

   bpf_log_debug("Packet received from interface %d", ctx->ingress_ifindex);

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_htons(ETH_P_IP)) {
      goto drop;
   }

   /* TODO 2: Parse IPv4 packet. Drop all non IPv4 packets */

   /* TODO 4: Check if IP destination is in the blocklist 
    * If it is, drop the packet, but increment a counter in the map
    * with both the number of packets and the number of bytes dropped
    * for a given IP address.
    * 
    * If the IP address is not in the blocklist, pass the packet.
    */


drop:
   bpf_log_debug("Dropping packet");
   return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";