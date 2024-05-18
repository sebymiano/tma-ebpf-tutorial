#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include <argparse.h>
#include <net/if.h>

#include "sk_skb_filter.skel.h"
#include "log.h"

#define DEFAULT_LPORT 10000
#define MAX_MSG_SIZE 50

#define DEFAULT_MSG_TO_COMPARE "Hello world"
#define DEFAULT_MSG_TO_ADD " from eBPF socket filter"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static const char *const usages[] = {
    "sk_skb_filter [options] [[--] args]",
    "sk_skb_filter [options]",
    NULL,
};

int main(int argc, const char **argv) {
    const char *ebpf_msg = NULL;
    const char *ebpf_msg_to_compare = NULL;
    int port = DEFAULT_LPORT;
    int err;
    struct sk_skb_filter_bpf *skel;
    char final_ebpf_msg_to_add[MAX_MSG_SIZE];
    char final_ebpf_msg_to_compare[MAX_MSG_SIZE];
    // bool cgroup_attached = false;
    bool verdict_attached = false;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('m', "message", &ebpf_msg, "Message to add from the eBPF program",
                   NULL, 0, 0),
        OPT_STRING('c', "msg_compare", &ebpf_msg_to_compare,
                   "Message to compare from the eBPF program", NULL, 0, 0),
        OPT_INTEGER('p', "port", &port, "Port to filter", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\nThis software attaches an XDP program to the interface "
                      "specified in the input parameter",
                      "\nThe '-i' argument is used to specify the interface where to "
                      "attach the program");
    argc = argparse_parse(&argparse, argc, argv);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    // libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    if (port != 0) {
        if (port < 1 || port > 65535) {
            log_fatal("Invalid port number %d", port);
            exit(1);
        }
    } else {
        port = DEFAULT_LPORT;
    }

    log_info("Filtering on port %d", port);

    if (ebpf_msg_to_compare != NULL) {
        if (strlen(ebpf_msg_to_compare) > MAX_MSG_SIZE) {
            log_fatal("Message too long, max size is %d", MAX_MSG_SIZE);
            exit(1);
        }
        snprintf(final_ebpf_msg_to_compare, MAX_MSG_SIZE, "%s", ebpf_msg_to_compare);
        log_info("Message to compare from eBPF: %s", final_ebpf_msg_to_compare);
    } else {
        // Write default message on the final_ebpf_msg_to_compare string
        snprintf(final_ebpf_msg_to_compare, MAX_MSG_SIZE, DEFAULT_MSG_TO_COMPARE);
        log_info("No message to compare from eBPF, using default message: %s",
                 final_ebpf_msg_to_compare);
    }

    if (ebpf_msg != NULL) {
        if (strlen(ebpf_msg) > MAX_MSG_SIZE) {
            log_fatal("Message too long, max size is %d", MAX_MSG_SIZE);
            exit(1);
        }
        snprintf(final_ebpf_msg_to_add, MAX_MSG_SIZE, "%s", ebpf_msg);
        log_info("Append message from eBPF: %s", final_ebpf_msg_to_add);
    } else {
        // Write default message on the final_ebpf_msg string
        snprintf(final_ebpf_msg_to_add, MAX_MSG_SIZE, DEFAULT_MSG_TO_ADD);
        log_info("No message from eBPF, using default message: %s",
                 final_ebpf_msg_to_add);
    }

    skel = sk_skb_filter_bpf__open();
    if (!skel) {
        log_error("Failed to open BPF skeleton");
        exit(1);
    }

    strncpy(skel->rodata->msg_to_add, final_ebpf_msg_to_add, MAX_MSG_SIZE);
    skel->rodata->msg_to_add_size = strlen(final_ebpf_msg_to_add);
    strncpy(skel->rodata->msg_to_compare, final_ebpf_msg_to_compare, MAX_MSG_SIZE);
    skel->rodata->msg_to_compare_size = strlen(final_ebpf_msg_to_compare);
    skel->rodata->local_port_to_filter = port;

    err = sk_skb_filter_bpf__load(skel);
    if (err) {
        log_error("Failed to load and verify BPF skeleton");
        exit(1);
    }

    int cg_fd = open("/sys/fs/cgroup/unified/", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        log_error("failed to open cgroup: %s", strerror(errno));
        exit(1);
    }

    bpf_program__set_expected_attach_type(skel->progs.bpf_sockops, BPF_CGROUP_SOCK_OPS);
    skel->links.bpf_sockops =
        bpf_program__attach_cgroup(skel->progs.bpf_sockops, cg_fd);
    if (skel->links.bpf_sockops == NULL) {
        log_error("Failed to attach sockops:  %s", strerror(errno));
        exit(1);
    }
    /* Use bpf_link, which is the new way to attach BPF programs */
    /* Below, is the OLD way */
    // err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_sockops), cg_fd,
    //                       BPF_CGROUP_SOCK_OPS, 0);
    // if (err < 0) {
    //     log_error("Failed to attach sockops: %s", strerror(errno));
    //     exit(1);
    // }
    // cgroup_attached = true;

    int sockmap_fd = bpf_map__fd(skel->maps.sock_map);
    if (sockmap_fd < 0) {
        log_error("Failed to get sockmap fd: %s", strerror(errno));
        goto cleanup;
    }

    /* Use bpf_link, which is the new way to attach BPF programs */
    /* This requires a new kernel */
    // bpf_program__set_expected_attach_type(skel->progs.bpf_sk_skb_filter,
    // BPF_SK_SKB_VERDICT); skel->links.bpf_sk_skb_filter =
    // bpf_program__attach_sockmap(skel->progs.bpf_sk_skb_filter, sockmap_fd); if
    // (skel->links.bpf_sk_skb_filter == NULL) {
    //     log_error("Failed to attach sk_skb_filter: %s", strerror(errno));
    //     goto cleanup;
    // }

    /* Use bpf_link, which is the new way to attach BPF programs */
    /* Below, is the OLD way */

    err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_sk_skb_filter), sockmap_fd,
                          BPF_SK_SKB_VERDICT, 0);
    if (err < 0) {
        log_error("Failed to attach sk_skb_filter: %s", strerror(errno));
        goto cleanup;
    }
    verdict_attached = true;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF program.\n");

    while (!exiting) {
        fprintf(stderr, ".");
        sleep(5);
    }

cleanup:
    /* If we use BPF links, we do not need to manually detach */
    // if (cgroup_attached)
    //     bpf_prog_detach2(bpf_program__fd(skel->progs.bpf_sockops), cg_fd,
    //     BPF_CGROUP_SOCK_OPS);
    log_debug("Detachig programs");
    if (verdict_attached)
        bpf_prog_detach2(bpf_program__fd(skel->progs.bpf_sk_skb_filter), sockmap_fd,
                         BPF_SK_SKB_VERDICT);
    sk_skb_filter_bpf__destroy(skel);
    return -err;
}