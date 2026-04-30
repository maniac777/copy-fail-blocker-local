# copy-fail-blocker

BPF-LSM mitigation for [CVE-2026-31431](https://copy.fail/) ("Copy Fail") and
similar privilege-escalation vulnerabilities that depend on userspace access
to the Linux kernel crypto API (`AF_ALG` / `algif_*`).

A small DaemonSet attaches a single BPF-LSM program to the `socket_create`
hook on every node. The program returns `-EPERM` for any `socket(AF_ALG, ...)`
call, regardless of process capabilities, namespace, or seccomp profile.

Tested on Talos Linux (which ships with `CONFIG_BPF_LSM=y` and `bpf` in the
default LSM stack since v1.10), works on any distribution with the same
kernel configuration.

## Why

CVE-2026-31431 is a logic flaw in `algif_aead` that lets an unprivileged
local user perform a 4-byte page-cache write to any setuid binary, achieving
root with a 732-byte Python script. The exploit needs nothing but
`AF_ALG` + `splice()`, both of which are reachable from any unprivileged
process by default.

The proper fix is a kernel patch (mainline `a664bf3d603d`). Until that lands
in your distribution, the attack surface can be removed by preventing
userspace from ever opening an `AF_ALG` socket. Compared to alternatives:

| Mitigation                                  | Coverage                | Reboot? | Persists? |
| ------------------------------------------- | ----------------------- | ------- | --------- |
| `module_blacklist=algif_aead` (kernel arg)  | host-wide               | yes     | yes       |
| Custom kernel without `CRYPTO_USER_API_AEAD`| host-wide               | yes     | yes       |
| Per-pod custom seccomp profile              | only labelled workloads | no      | yes       |
| **copy-fail-blocker (this project)**        | **host-wide**           | **no**  | while DS runs |

This project is the no-reboot option. Run it cluster-wide, then plan the
permanent kernel fix on your normal patch cadence.

## How it works

`bpf/blocker.c` is a 15-line BPF-LSM program:

```c
SEC("lsm/socket_create")
int BPF_PROG(block_af_alg, int family, int type, int protocol,
             int kern, int ret)
{
    if (ret)
        return ret;
    if (family == AF_ALG)   // 38
        return -EPERM;
    return 0;
}
```

The Go loader (`main.go`, ~40 lines) loads the program and attaches it via
`bpf(BPF_LINK_CREATE)`. The link is held for the lifetime of the pod. On
`SIGTERM`, the link is closed and the hook detaches.

Requires a kernel built with `CONFIG_BPF_LSM=y` and `bpf` in the active LSM
stack (`lsm=...,bpf` on the kernel command line). Talos Linux ships with
both enabled by default since v1.10.

## Install

### kubectl

```sh
kubectl apply -f https://raw.githubusercontent.com/cozystack/copy-fail-blocker/v0.2.1/manifests/copy-fail-blocker.yaml
```

For the latest commit on `main` (may include unreleased changes):

```sh
kubectl apply -f https://raw.githubusercontent.com/cozystack/copy-fail-blocker/main/manifests/copy-fail-blocker.yaml
```

### Helm

The chart is not published as an OCI artifact (the registry path is shared
with the container image). Install from a tagged checkout:

```sh
git clone --branch v0.2.1 https://github.com/cozystack/copy-fail-blocker
cd copy-fail-blocker
helm upgrade --install copy-fail-blocker charts/copy-fail-blocker \
  --namespace kube-system
```

Or via the Makefile shortcuts:

```sh
make apply         # helm upgrade --install into kube-system
make diff          # preview changes against the cluster
make delete        # uninstall
make manifest      # regenerate manifests/copy-fail-blocker.yaml
```

The DaemonSet must run privileged (it loads BPF programs and writes to
bpffs). Place it in a namespace with the privileged Pod Security Standard,
or in `kube-system`, which is privileged by default.

## Verify

From any pod on a covered node:

```sh
python3 -c '
import socket
try:
    socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print("FAIL: AF_ALG socket created")
except OSError as e:
    print("OK:", e)'
```

Expected output:

```
OK: [Errno 1] Operation not permitted
```

## Build

```sh
make image                                       # docker buildx build + push
make image REGISTRY=ghcr.io/myorg TAG=v0.2.1     # custom tag
make image PUSH=0 LOAD=1                         # build locally without pushing
```

`make image` updates `charts/copy-fail-blocker/values.yaml` with the
resolved image digest so the chart always pins by digest.

Build dependencies live in the Containerfile (clang, libbpf-dev, Go). Local
host needs only `docker buildx`, `helm`, `yq` (mikefarah), `kubectl`, and
`helm-diff`.

## Configuration

`charts/copy-fail-blocker/values.yaml`:

| Key                   | Default                              | Notes                                  |
| --------------------- | ------------------------------------ | -------------------------------------- |
| `image.repository`    | `ghcr.io/cozystack/copy-fail-blocker`| Auto-updated by `make image`           |
| `image.tag`           | `v0.1.0@sha256:...`                  | Pinned by digest                       |
| `priorityClassName`   | `system-node-critical`               | Ensures the daemon survives evictions  |
| `tolerations`         | `[{operator: Exists}]`               | Runs on every node, including tainted  |
| `resources.requests`  | `5m CPU / 16Mi memory`               | Idle footprint after attach            |

## Limitations

- **The hook lives only while the pod runs.** On pod restart there is a
  short window (seconds) where `AF_ALG` is reachable again. For most
  threat models this is acceptable; if not, consider pinning the BPF link
  to bpffs (not implemented here — see [issues](https://github.com/cozystack/copy-fail-blocker/issues)).
- **Anyone with `CAP_BPF` and `CAP_SYS_ADMIN`** on the host can detach the
  hook. This is not a substitute for cluster-wide privilege restrictions.
- **Does not block `algif_skcipher` / `algif_hash` / etc.** The program
  rejects the entire `AF_ALG` family, but only `algif_aead` is currently
  known to be exploitable. If a future CVE needs a finer filter (e.g. hook
  `bind()` and inspect `salg_type`), this is straightforward to add.
- **No effect on processes that already hold an open `AF_ALG` socket.**
  Existing sockets keep working until closed.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
