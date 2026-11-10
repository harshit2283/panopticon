// SPDX-License-Identifier: GPL-2.0
/*
 * Count the elements of an sk_storage map (T-12, scope_lab.py t12): one
 * "e" line per socket that holds storage in the map. `bpftool map dump`
 * cannot list sk_storage maps (they have no get_next_key), a map iterator
 * can (Linux 5.9+):
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 *   clang -O2 -g -target bpf -c sk_storage_count.bpf.c -o sk_storage_count.bpf.o
 *   bpftool iter pin sk_storage_count.bpf.o /sys/fs/bpf/cnt map id ID
 *   wc -l < /sys/fs/bpf/cnt
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("iter/bpf_sk_storage_map")
int count_elems(struct bpf_iter__bpf_sk_storage_map *ctx)
{
	/* On the stack, not a string literal: older libbpf (5.15, RHEL 8)
	 * cannot relocate .rodata.str1.1. */
	char line[2] = {'e', '\n'};

	if (ctx->sk && ctx->value)
		bpf_seq_write(ctx->meta->seq, line, sizeof(line));
	return 0;
}
