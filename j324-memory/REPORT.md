<!-- J324 memory experiment: method, provenance and limits for issue #407 / #260. -->
# J324: memory pools

Work in progress on `j324-mem-pools`, based on `ebeb8f0071c4103168b570407f9dc555562f4b79`.
Tracked in https://git.kayg.org/kayg/infraternal/issues/407, coordinated on #260.
No infraternal dependency pin changes. No allocator or crypto library replacement.

## Baseline diagnostic

Measured on `infraternal-perf-01-backup01`, through `perf-run --root` and the
existing D348 placement/audit wrapper. Endpoints use CPUs 1–2 and 3–4; the
coordinator and host work use 0,5. Both kernel and userspace engines use the
same MTU 1420. A case takes about 2 minutes; the kernel/Go comparison shared
a 4.4-minute lock window. These memory diagnostics do not establish D348
throughput or latency acceptance. Three-control calibration is separate.

Each row counts **both endpoints combined**, with the indicated peer count
on **each** endpoint. One peer is established and carries eight TCP flows;
the other peers are configured, unhandshaken, without endpoints or keepalives.
Scale grows sequentially 1 → 100 → 1,000 in one process pair. Consequently,
later idle samples include allocator retention from earlier load. The method
is identical for all engines. Idle CPU is sampled over 5 seconds. Loaded RSS
is sampled 3 seconds into a 10-second load; recovered RSS is sampled 12 seconds
after the probe finishes. Raw throughput files also retain the sampled RSS peak.

| Engine | Peers/endpoint | Idle RSS MiB | Loaded RSS MiB | Recovered RSS MiB | Idle CPU % of one core |
|---|---:|---:|---:|---:|---:|
| GotaTun base | 1 | 9.211 | 29.414 | 11.297 | 0.0 |
| GotaTun base | 100 | 11.707 | 32.461 | 11.738 | 0.0 |
| GotaTun base | 1,000 | 15.961 | 36.074 | 15.508 | 0.0 |
| wireguard-go | 1 | 29.309 | 642.695 | 929.770 | 0.0 |
| wireguard-go | 100 | 933.910 | 938.848 | 1,078.656 | 0.0 |
| wireguard-go | 1,000 | 1,111.145 | 1,115.727 | 1,203.863 | 0.2 |
| kernel | 1 / 100 / 1,000 | N/A | N/A | N/A | N/A |

Kernel WireGuard has no daemon RSS. Its raw `proc-mem` results are zero, which
is not zero kernel memory. Whole-scope `memory.stat`, kernel work audit and
softirq deltas are retained, but do not isolate per-peer kernel allocation.
The historical ~1.65 KiB/kernel-peer figure is a reference, not remeasured by
these process RSS samples. The five-second zero-CPU readings mean no CPU tick
was counted, rather than proof of zero work or wakeups.

Artifacts on the perf VM:

- `/home/claude/j324/evidence/base/base/mesh-gotatun/`
- `/home/claude/j324/evidence/competitors/kernel/mesh-kernel-plain/`
- `/home/claude/j324/evidence/competitors/wireguard-go/mesh-wireguard-go/`
- `/home/claude/j324/evidence/base-console.log` (exit 0)
- `/home/claude/j324/evidence/competitors-console.log` (exit 0)

Every phase retains process status, PSS/RSS from `smaps_rollup`, and `/proc/PID/io`.
Each load window retains raw ICMP probes and the runnable-task/CPU audit.
The case machine diffs were empty. Post-scope restoration is also checked
separately for calibration windows using the existing restore verifier.

## Allocation inventory and candidate boundaries

The base already owns one lazy packet pool per device connection, shared across
peers and directions, retaining at most 4,000 4 KiB buffers. Its capacity is
not multiplied by peer count. Idle release drops the returned buffers and deque
storage, then calls the existing glibc trim hook. Each Linux UDP receiver has
a separate 100 × 256 KiB GRO scratch allocation, with idle page discard.
The Linux TUN has its own large frame scratch allocation for offloads.

Per peer: compact allowed-IP metadata, tunnel/handshake state, timer deadlines
scanned by a device-wide timer task, a shared rate-limiter reference, handshake
notification state, and a lazy blocked-packet deque capped at 256 entries.
The eight-slot session ring is allocated only after a handshake. The blocked
packet deque is initially empty but its descriptor capacity currently survives
drain/reset. Payloads are drawn from the device pool rather than a per-peer pool.

The first candidate keeps the existing pool and adds a smaller packet size
class while keeping a single endpoint-wide retention bound. Known MTU-sized
packets can use the smaller class; large/offload frames retain their existing
growth fallback. The second releases peer queue storage after drain/reset.
Neither candidate changes crypto ordering, TUN coalescing, receive truncation
policy, queue admission bounds, the engine, or the shipping allocator.

Heap attribution and candidate results are pending. The temporary diagnostic
binary uses the existing optional jemalloc feature and reports allocator bins;
it is separate from the shipping-system-allocator timing binary.

## Reproduction

`scale-overlay.patch` applies to `cases/mesh.sh` in the existing J88i pinned
R4b kit at `/home/claude/j88i-r4b-pinned/harness` on the perf VM. Clone the kit
into a job-specific directory (reuse its binary/library files), apply the patch,
and run through `perf-run --root` and `runner-overlays/J88i-pinned-run.sh`.
Use a row TSV selecting `gotatun`, `kernel-plain`, or `wireguard-go`. The base
binary is `/home/claude/j324/gotatun-base` with raw executable
`/home/claude/j324/gotatun-base.raw`; it launches with the same copied runtime
as J88i. Never run outside the performance lock.

`lan-overlay.patch` instead retains only the unchanged LAN profile with 3,600
raw probes per 1/8-flow case and ten-second load intervals. It removes WAN and
scale work so each calibration window can release the lock promptly. Three
separate baseline windows feed the existing `lib/calibration_spread.py`, with
the existing 1.6%/0.8% throughput and 3.2%/5.9% p99 spread limits.

This report/evidence slice changes no shipping code; the infraternal gate does
not apply to it. Fork correctness checks will precede production pool changes.
