#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("drop-all")
int drop(struct xdp_md *ctx) {
	return XDP_DROP;
}
