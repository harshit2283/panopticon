// A foreign cgroup/setsockopt program that rewrites a call's level and
// option: setsockopt(SOL_TCP, 1000, buf) becomes setsockopt(SOL_TLS,
// TLS_RX, buf), so a kTLS key is installed by a call the application made
// at another level (DESIGN T-21: the key-install marker sees the level the
// kernel goes on with). Used by panopticon-agent/tests/scope_attach.rs
// (SOCKOPT_REWRITE_OBJ). Build:
//   clang-18 -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c sockopt_rewrite.bpf.c
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("cgroup/setsockopt")
int sockopt_rewrite(struct bpf_sockopt *ctx)
{
	if (ctx->level == 6 && ctx->optname == 1000) {
		// Volatile: two 32-bit context stores (clang would merge them into
		// one 64-bit store, which the verifier refuses).
		*(volatile __u32 *)&ctx->level = 282; // SOL_TLS
		*(volatile __u32 *)&ctx->optname = 2; // TLS_RX
	}
	return 1;
}

char _license[] SEC("license") = "GPL";
