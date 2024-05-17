#ifndef DROP_IP_H_
#define DROP_IP_H_

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>

#include <cyaml/cyaml.h>
#include <sys/types.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>

#include "log.h"

// Include skeleton file
#include "drop_ip.skel.h"

static int ifindex_iface = 0;
static __u32 xdp_flags = 0;

struct ip {
    const char *ip;
};

struct blocklist_dsts {
    struct ip *ips;
    uint64_t ips_count;
};

static const cyaml_schema_field_t ip_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct ip, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t ip_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct ip, ip_field_schema),
};

static const cyaml_schema_field_t blocklist_dsts_field_schema[] = {
    CYAML_FIELD_SEQUENCE("blocklist_dsts", CYAML_FLAG_POINTER, struct blocklist_dsts,
                         ips, &ip_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t blocklist_dsts_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct blocklist_dsts,
                        blocklist_dsts_field_schema),
};

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface != 0) {
        if (!bpf_xdp_query_id(ifindex_iface, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface);
            }
        }
    }
}

int attach_bpf_progs(unsigned int xdp_flags, struct drop_ip_bpf *skel) {
    int err = 0;
    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface, bpf_program__fd(skel->progs.xdp_drop_by_ip),
                         xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching XDP program to the interface");
        return err;
    }

    return 0;
}

static void get_iface_ifindex(const char *iface) {
    if (iface == NULL) {
        log_warn("No interface specified, using default one (veth1)");
        iface = "veth1";
    }

    log_info("XDP program will be attached to %s interface", iface);
    ifindex_iface = if_nametoindex(iface);
    if (!ifindex_iface) {
        log_fatal("Error while retrieving the ifindex of %s", iface);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface, ifindex_iface);
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

#endif // DROP_IP_H_
