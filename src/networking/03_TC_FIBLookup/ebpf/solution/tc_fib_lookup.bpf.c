// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_log.h"

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define AF_INET 2
#define ETH_ALEN 6 /* Octets in one ethernet addr	 */

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    __u8 zero[ETH_ALEN * 2];

    if (ctx->protocol != bpf_htons(ETH_P_IP)) {
        bpf_log_err("Not an IP packet: protocol: %d", ctx->protocol);
        return TC_ACT_OK;
    }

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_log_info("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len),
                 l3->ttl);

    /* Let's perform a lookup into the kernel FIB */
    /* More info here:
     * https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_fib_lookup/
     */
    struct bpf_fib_lookup fib_params = {
        .family = AF_INET,
        .tos = l3->tos,
        .l4_protocol = l3->protocol,
        .sport = 0,
        .dport = 0,
        .tot_len = bpf_ntohs(l3->tot_len),
        .ipv4_src = l3->saddr,
        .ipv4_dst = l3->daddr,
        .ifindex = ctx->ingress_ifindex,
    };

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (ret == BPF_FIB_LKUP_RET_NOT_FWDED || ret < 0) {
        bpf_log_err("FIB lookup failed: %d", ret);
        return TC_ACT_OK;
    }

    /* Let's zero out the src and dst MAC */
    __builtin_memset(&zero, 0, sizeof(zero));
    if (bpf_skb_store_bytes(ctx, 0, &zero, sizeof(zero), 0) < 0) {
        bpf_log_err("Zero out MAC failed");
        return TC_ACT_SHOT;
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
        bpf_log_info("No neighbor found");
        bpf_log_info("Redirecting packet to ifindex: %d", fib_params.ifindex);

        /* Let's call the redirect with the neighbor lookup */
        /* More info here:
         * https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_redirect_neigh/
         *
         * Redirect the packet to another net device of index ifindex and
         * fill in L2 addresses from neighboring subsystem
         */

        struct bpf_redir_neigh neigh_params = {.nh_family = fib_params.family,
                                               .ipv4_nh = fib_params.ipv4_dst};

        ret = bpf_redirect_neigh(fib_params.ifindex, &neigh_params,
                                 sizeof(neigh_params), 0);
        if (ret == TC_ACT_SHOT) {
            bpf_log_err("Redirect neigh failed: %d", ret);
            return TC_ACT_SHOT;
        }

        return ret; // TC_ACT_REDIRECT
    } else if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_log_info("FIB lookup success, redirecting packet to ifindex: %d",
                     fib_params.ifindex);

        __builtin_memcpy(l2->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(l2->h_source, fib_params.smac, ETH_ALEN);

        return bpf_redirect(fib_params.ifindex, 0);
    }

    bpf_log_err("FIB lookup returned unsupported value: %d", ret);
    return TC_ACT_SHOT;
}

SEC("tc")
int tc_chk(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    __u32 *raw = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_SHOT;

    return !raw[0] && !raw[1] && !raw[2] ? TC_ACT_SHOT : TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";