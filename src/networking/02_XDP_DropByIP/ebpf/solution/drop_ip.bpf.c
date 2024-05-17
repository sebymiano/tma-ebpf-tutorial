#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bpf_log.h"

#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

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
   // eth->h_proto = 14;
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   struct iphdr *ip = (struct iphdr *)(data + *nh_off);
   int hdr_size = sizeof(*ip);

   /* Byte-count bounds check; check if current pointer + size of header
    * is after data_end.
    */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   hdr_size = ip->ihl * 4;
   if (hdr_size < sizeof(*ip))
      return -1;

   /* Variable-length IPv4 header, need to use byte-based arithmetic */
   if ((void *)ip + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol;
}

SEC("xdp")
int xdp_drop_by_ip(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   struct iphdr *ip;
   int eth_type, ip_type;
   int action = XDP_PASS;

   bpf_log_debug("Packet received from interface %d", ctx->ingress_ifindex);

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_htons(ETH_P_IP)) {
      bpf_log_err("Packet is not an IPv4 packet");
      goto drop;
   }

   ip_type = parse_iphdr(data, data_end, &nf_off, &ip);

   if (ip_type < 0) {
      bpf_log_err("Packet is not a valid IPv4 packet");
      goto drop;
   }

   struct datarec *val = bpf_map_lookup_elem(&blocklist_dst, &ip->daddr);
   if (!val) {
      bpf_log_debug("IP %d is not in the blocklist", ip->daddr);
      bpf_log_debug("Passing packet");
      goto pass;
   }

   bpf_log_debug("IP %d is in the blocklist", ip->daddr);
   __u64 bytes = data_end - data;
   __sync_fetch_and_add(&val->rx_packets, 1);
   __sync_fetch_and_add(&val->rx_bytes, bytes);

   goto drop;

drop:
   bpf_log_debug("Dropping packet");
   return XDP_DROP;

pass:
   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";