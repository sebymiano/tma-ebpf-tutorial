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
int tc_fib_lookup(struct __sk_buff *ctx) {
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;

    __u8 zero[ETH_ALEN * 2];

    /* TODO 1: Parse L2 and L3 headers */

    /* TODO 2: Let's perform a lookup into the kernel FIB */
    /* More info here:
     * https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_fib_lookup/
     */
    struct bpf_fib_lookup fib_params = {};

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (ret == BPF_FIB_LKUP_RET_NOT_FWDED || ret < 0) {
        /* TODO 3: packet cannot be forwarded, continue processing and stop eBPF program
         */
    }

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
        bpf_log_info("No neighbor found");
        bpf_log_info("Redirecting packet to ifindex: %d", fib_params.ifindex);

        /* TODO 4: Let's call the redirect with the neighbor lookup */
        /* More info here:
         * https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_redirect_neigh/
         *
         * Redirect the packet to another net device of index ifindex and
         * fill in L2 addresses from neighboring subsystem
         */

        return TC_ACT_OK;
    } else if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        bpf_log_info("FIB lookup success, redirecting packet to ifindex: %d",
                     fib_params.ifindex);

        /* TODO 5: Redirect the packet to another net device of index ifindex
         * and fill in L2 addresses from the FIB lookup
         */

        return TC_ACT_OK;
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