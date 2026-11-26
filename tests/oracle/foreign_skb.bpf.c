// An unrelated cgroup_skb program for run_scope.sh coexist (DESIGN T-16):
// counts packets and allows them all. Attached with BPF_F_ALLOW_MULTI to
// the cgroup2 root next to the agent's programs.
//   clang -O2 -g -target bpf -c foreign_skb.bpf.c -o foreign_skb.bpf.o
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} b2_count SEC(".maps");

SEC("cgroup_skb/egress")
int b2_foreign(struct __sk_buff *skb)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&b2_count, &k);
	if (v)
		__sync_fetch_and_add(v, 1);
	return 1;
}

char _license[] SEC("license") = "GPL";
