#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_log.h"

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

static __always_inline bool _pull_and_validate_data(struct __sk_buff *skb, void **data_,
                                                    void **data_end_, uint16_t size) {
    int err;
    void *data, *data_end;
    bpf_skb_pull_data(skb, size);

    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    if (data + size > data_end) {
        bpf_log_err("Unable to pull %d data from skb\n", size);
        return false;
    }

    *data_end_ = (void *)(long)skb->data_end;
    *data_ = (void *)(long)skb->data;

    return true;
}

const char *msg = "Hello world";
const char *msg2 = " from eBPF socket filter";

SEC("sk_skb")
int bpf_sk_skb_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u32 lport = skb->local_port;

    if (lport != 10000)
        return SK_PASS;

    if (!_pull_and_validate_data(skb, &data, &data_end, skb->len)) {
        bpf_log_err("Unable to pull data from skb");
        return SK_DROP;
    }

    char *buf = data;

    int ret = bpf_strncmp(buf, sizeof(msg), msg);
    if (ret == 0) {
        bpf_log_debug("Packet contains %s", msg);
        return SK_DROP;
    }

    return SK_PASS;
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    __u32 lport, rport;
    int op, err = 0, index, key, ret;

    op = (int)skops->op;

    int key = 0;
    /*
     * args[0]: old_state
     * args[1]: new_state
     */
    if (op == BPF_SOCK_OPS_STATE_CB && skops->args[1] == BPF_TCP_CLOSE) {
        if (skops->local_port == 10000) {
            bpf_log_debug("Socket closed. Delete sockmap entry at key: %d", key);
            bpf_map_delete_elem(&sock_map, &key);
        }
        return 0;
    }

    if (op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        /* This is used for incoming connections
         * The program is invoked with this op when a active socket transitioned to have
         * an established connection. This happens when a incoming connection
         * establishes. This is just a notification, return value is discarded.
         *
         * https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_SOCK_OPS/
         */
        bpf_log_debug("New socket added with IP src: %u, IP dst: %u", skops->local_ip4,
                      skops->remote_ip4);
        bpf_log_debug("New socket added with TCP src port: %u, TCP dst port: %u",
                      skops->local_port, bpf_ntohl(skops->remote_port));

        if (skops->local_port == 10000) {
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
                                                 BPF_SOCK_OPS_STATE_CB_FLAG);
            bpf_sock_map_update(skops, &sock_map, &key, BPF_ANY);
        }
    }

    return 0;
}