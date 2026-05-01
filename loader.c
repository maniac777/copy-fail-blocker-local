#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "blocker.skel.h"

int main(int argc, char **argv)
{
    struct blocker *skel;
    int err;

    skel = blocker__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = blocker__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = blocker__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    int map_fd = bpf_map__fd(skel->maps.count);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map FD\n");
        goto cleanup;
    }

    printf("BPF program loaded and map updated. Press Ctrl+C to exit.\n");

   int lookup_key = 0;
   int oldcount = 0;
   int count = 0;
    while (1) {
        sleep(1);
        err = bpf_map__lookup_elem(skel->maps.count,
                                   &lookup_key, sizeof(lookup_key),
                                   &count, sizeof(count), 0);
        if (err == 0) {
	    if (count != oldcount) {
   	        time_t now = time(NULL);
		struct tm *tm_info = localtime(&now);
		char buf[32];
		strftime(buf, sizeof(buf), "%b %e %H:%M:%S", tm_info);
                printf("%s AF_ALG socket creation blocked\n", buf);
	    }
	    oldcount = count;
        } else {
            fprintf(stderr, "Lookup failed for key %d: %d\n", lookup_key, err);
        }
    }
cleanup:
    blocker__destroy(skel);
    printf("BPF program unloaded.\n");
    return 0;
}
