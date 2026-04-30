//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_ALG 38
#define EPERM  1

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/socket_create")
int BPF_PROG(block_af_alg, int family, int type, int protocol, int kern, int ret)
{
	if (ret)
		return ret;

	if (family == AF_ALG)
		return -EPERM;

	return 0;
}
