#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int drop_port(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) > data_end)
		return XDP_PASS;

	// this is only for IPv4
	struct iphdr *ipv4 = data + sizeof(*eth);
	if ((void*)ipv4 + sizeof(*ipv4) > data_end)
		return XDP_PASS;

	//TODO(Aurel): Find out how to parse IPv6

	if (ipv4->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void*)ipv4 + sizeof(*ipv4);
		if ((void*)tcp + sizeof(*tcp) > data_end)
			return XDP_PASS;

		bpf_printk("TCP packet destination: %i", tcp->dest);
	}

	return XDP_PASS;
}
