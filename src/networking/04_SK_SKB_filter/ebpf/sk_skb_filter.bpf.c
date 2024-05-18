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

#define MAX_MSG_SIZE 50

const char msg_to_compare[MAX_MSG_SIZE] = "Hello world";
const volatile uint8_t msg_to_compare_size = 11;
const char msg_to_add[MAX_MSG_SIZE] = " from eBPF socket filter";
const volatile uint8_t msg_to_add_size = 26;

const volatile int local_port_to_filter = 10000;

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

SEC("sk_skb")
int bpf_sk_skb_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u32 lport = skb->local_port;

    if (lport != local_port_to_filter)
        return SK_PASS;

    if (!_pull_and_validate_data(skb, &data, &data_end, skb->len)) {
        bpf_log_err("Unable to pull data from skb");
        return SK_DROP;
    }

    char buf[MAX_MSG_SIZE];
    if (data + msg_to_compare_size > data_end) {
        bpf_log_err(
            "Data is too big to fit in buffer. Required: 11 bytes, available: %ld",
            data_end - data);
        return SK_PASS;
    }

    bpf_log_debug("Message to compare: %s", msg_to_compare);
    bpf_log_debug("Message to add: %s", msg_to_add);

    for (int i = 0; i < msg_to_compare_size; i++) {
        buf[i] = ((char *)data)[i];
    }

    int ret = bpf_strncmp(buf, msg_to_compare_size, msg_to_compare);
    if (ret == 0) {
        bpf_log_debug("Packet contains %s", msg_to_compare);
        return SK_DROP;
    } else {
        bpf_log_debug("Packet does not contain %s", msg_to_compare);
        bpf_log_debug("Got: %s", buf);
        return SK_PASS;
    }

    return SK_PASS;
}

SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *skops) {
    __u32 lport, rport;
    int op, err = 0, index, ret;

    op = (int)skops->op;

    int key = 0;
    /*
     * args[0]: old_state
     * args[1]: new_state
     */
    if (op == BPF_SOCK_OPS_STATE_CB && skops->args[1] == BPF_TCP_CLOSE) {
        if (skops->local_port == local_port_to_filter) {
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

        if (skops->local_port == local_port_to_filter) {
            bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
                                                 BPF_SOCK_OPS_STATE_CB_FLAG);
            bpf_sock_map_update(skops, &sock_map, &key, BPF_ANY);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";