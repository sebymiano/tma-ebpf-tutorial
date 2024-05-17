// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int __always_inline compare_11_byte_strings(char *str1, const char str2[11]) {
#pragma clang loop unroll(full)
    for (int i = 0; i < 11; i++) {
        if (str1[i] != str2[i]) {
            return str1[i] - str2[i];
        }
    }
    return 0; // strings are equal
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter *a
rgs)
{
    const char *filename = (const char *)args->args[1];
    char fname[256];
    const char ftoblock[11] = "/etc/passwd";

    bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (compare_11_byte_strings(fname, "/etc/passwd") == 0) {
        // print to /sys/kernel/debug/tracing/trace_pipe
        bpf_printk("[!] PID %d tried to open /etc/passwd\n", bpf_get_current_pid_tgid() >> 32);

        bpf_probe_write_user((char*)args->args[1], "/dev/null", 10);
        //bpf_send_signal(9);
    }

    return 0;
}

