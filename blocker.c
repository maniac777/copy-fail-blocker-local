//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_ALG 38
#define EPERM  1

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} count SEC(".maps");

SEC("lsm/socket_create")
int BPF_PROG(block_af_alg, int family, int type, int protocol, int kern, int ret)
{
    int key = 0;
    int *value;

    if (ret)
    	return ret;
    
    if (family == AF_ALG) {
	/* logging */
        value = bpf_map_lookup_elem(&count, &key);
        if (value) {
            if (*value >= 65536) {
                *value = 0;
            } else {
                (*value)++;
            }
        }

    	return -EPERM;
    }
    
    return 0;
}
