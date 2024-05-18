// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
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

#include "tc_fib_lookup.skel.h"
#include "log.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) {
    exiting = 1;
}

static const char *const usages[] = {
    "tc_fib_lookup [options] [[--] args]",
    "tc_fib_lookup [options]",
    NULL,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static int get_iface_ifindex(const char *iface) {
    if (iface == NULL) {
        log_warn("No interface specified");
        return -1;
    }

    log_info("TC program will be attached to %s interface", iface);
    return if_nametoindex(iface);
}

static int create_bpf_tc_hook(struct bpf_tc_hook *tc_hook, int ifindex) {
    int err;

    tc_hook->ifindex = ifindex;
    tc_hook->attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
    err = bpf_tc_hook_create(tc_hook);
    if (err) {
        return err;
    }

    return 0;
}

static int attach_bpf_tc_hook(struct bpf_tc_hook *tc_hook,
                              enum bpf_tc_attach_point xgress,
                              const struct bpf_program *prog, int priority) {
    int err;
    LIBBPF_OPTS(bpf_tc_opts, tc_attach);
    char ifname[16];

    tc_hook->attach_point = xgress;
    tc_attach.prog_fd = bpf_program__fd(prog);
    tc_attach.priority = priority;
    tc_attach.handle = 1;

    err = bpf_tc_attach(tc_hook, &tc_attach);
    if (err) {
        log_fatal("filter add dev %s %s prio %d bpf da %s",
                  if_indextoname(tc_hook->ifindex, ifname) ?: "<unknown_iface>",
                  xgress == BPF_TC_INGRESS ? "ingress" : "egress", priority,
                  bpf_program__name(prog));
        return err;
    }

    return 0;
}

static int detach_bpf_tc_hook(struct bpf_tc_hook *tc_hook,
                              enum bpf_tc_attach_point xgress, int priority) {
    int err;
    LIBBPF_OPTS(bpf_tc_opts, tc_detach);

    tc_hook->attach_point = xgress;
    tc_detach.flags = tc_detach.prog_fd = tc_detach.prog_id = 0;
    tc_detach.priority = priority;
    tc_detach.handle = 1;

    err = bpf_tc_detach(tc_hook, &tc_detach);
    if (err) {
        log_fatal("Error while detaching filter");
        return err;
    }

    return 0;
}

int main(int argc, const char **argv) {
    const char *iface_src = NULL;
    const char *iface_dst = NULL;
    int ifindex_src = 0;
    int ifindex_dst = 0;
    int err;
    bool src_hook_created = false;
    bool dst_hook_created = false;
    struct tc_fib_lookup_bpf *skel;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('1', "src", &iface_src,
                   "Source interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('2', "dst", &iface_dst,
                   "Destination interface where to attach the BPF program", NULL, 0, 0),
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

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Get source ifindex */
    ifindex_src = get_iface_ifindex(iface_src);

    if (!ifindex_src) {
        log_fatal("Error while retrieving the ifindex of %s", iface_src);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface_src, ifindex_src);
    }

    /* Get destination ifindex */
    ifindex_dst = get_iface_ifindex(iface_dst);

    if (!ifindex_dst) {
        log_fatal("Error while retrieving the ifindex of %s", iface_dst);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface_dst, ifindex_dst);
    }

    skel = tc_fib_lookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    LIBBPF_OPTS(bpf_tc_hook, src_tc_hook);
    LIBBPF_OPTS(bpf_tc_hook, dst_tc_hook);

    err = create_bpf_tc_hook(&src_tc_hook, ifindex_src);
    if (!err)
        src_hook_created = true;
    if (err && err != -EEXIST) {
        log_fatal("Failed to create source TC hook: %s", strerror(-err));
        goto cleanup;
    }

    err = create_bpf_tc_hook(&dst_tc_hook, ifindex_dst);
    if (!err)
        dst_hook_created = true;
    if (err && err != -EEXIST) {
        log_fatal("Failed to create destination TC hook: %s", strerror(-err));
        goto cleanup;
    }

    /* Attach the BPF program to the source TC hook */
    err =
        attach_bpf_tc_hook(&src_tc_hook, BPF_TC_INGRESS, skel->progs.tc_fib_lookup, 1);
    if (err) {
        log_fatal("Failed to attach tc_fib_lookup to source TC hook: %s",
                  strerror(-err));
        goto cleanup;
    }

    err = attach_bpf_tc_hook(&src_tc_hook, BPF_TC_EGRESS, skel->progs.tc_chk, 1);
    if (err) {
        log_fatal("Failed to attach tc_chk to source TC hook: %s", strerror(-err));
        goto cleanup;
    }

    /* Attach the BPF programs to the destination TC hook */
    err =
        attach_bpf_tc_hook(&dst_tc_hook, BPF_TC_INGRESS, skel->progs.tc_fib_lookup, 1);
    if (err) {
        log_fatal("Failed to attach tc_fib_lookup to destination TC hook: %s",
                  strerror(-err));
        goto cleanup;
    }

    err = attach_bpf_tc_hook(&dst_tc_hook, BPF_TC_EGRESS, skel->progs.tc_chk, 1);
    if (err) {
        log_fatal("Failed to attach tc_chk to destination TC hook: %s", strerror(-err));
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        log_fatal("Failed to set signal handler: %s", strerror(err));
        goto cleanup;
    }

    log_info("Successfully started! Please run `sudo cat "
             "/sys/kernel/debug/tracing/trace_pipe` "
             "to see output of the BPF program.\n");

    while (!exiting) {
        fprintf(stderr, ".");
        sleep(5);
    }

    log_info("\nExiting...\n");

    /* Detach the BPF programs from the source TC hook */
    err = detach_bpf_tc_hook(&src_tc_hook, BPF_TC_INGRESS, 1);
    if (err) {
        log_fatal("Failed to detach tc_fib_lookup from source TC hook: %s",
                  strerror(-err));
    }

    err = detach_bpf_tc_hook(&src_tc_hook, BPF_TC_EGRESS, 1);
    if (err) {
        log_fatal("Failed to detach tc_chk from source TC hook: %s", strerror(-err));
    }

    /* Detach the BPF programs from the destination TC hook */
    err = detach_bpf_tc_hook(&dst_tc_hook, BPF_TC_INGRESS, 1);
    if (err) {
        log_fatal("Failed to detach tc_fib_lookup from destination TC hook: %s",
                  strerror(-err));
    }

    err = detach_bpf_tc_hook(&dst_tc_hook, BPF_TC_EGRESS, 1);
    if (err) {
        log_fatal("Failed to detach tc_chk from destination TC hook: %s",
                  strerror(-err));
    }

cleanup:
    if (src_hook_created)
        bpf_tc_hook_destroy(&src_tc_hook);
    if (dst_hook_created)
        bpf_tc_hook_destroy(&dst_tc_hook);
    tc_fib_lookup_bpf__destroy(skel);
    return -err;
}