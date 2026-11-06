<!-- J324 memory experiment: method, provenance and limits for issue #407 / #260. -->
# J324: memory pools

Experimental candidate on `j324-mem-pools`, based on `ebeb8f0071c4103168b570407f9dc555562f4b79`.
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

## Matched-build baseline and calibration blocker

The reused diagnostic executable above has SHA-256
`15a9bfd659ce2a74f7c58acc22c644b7b239de5fba12be85a10e53d640ee41e9`.
The baseline rebuilt for pairing with the candidate has SHA-256
`84e342a623596f5bac78156018e0df3753498c930f7f4f82fdb73e06a809b8b7`.
Both identify the same source base; they are separate artifacts. Only the
second baseline is suitable for the candidate's matching build comparison.
It uses the fork flake's rustc 1.95.0 (`59807616e`, LLVM 22.1.2), existing
release LTO/codegen settings and the system allocator. Compiler evidence:
compute01 `/home/claude/j324-evidence/compiler.txt`.

| Peers/endpoint | Idle RSS MiB | Loaded RSS MiB | Sampled peak MiB | Recovered MiB | Idle CPU % |
|---|---:|---:|---:|---:|---:|
| 1 | 9.125 | 30.043 | 33.086 | 11.242 | 0.0 |
| 100 | 11.641 | 31.871 | 32.105 | 11.805 | 0.0 |
| 1,000 | 15.914 | 35.156 | 36.477 | 15.688 | 0.4 |

Artifacts: perf VM `/home/claude/j324/evidence/base-built/base/mesh-gotatun`,
`base-built-console.log` (exit 0), and `memory-summary.md`. These remain
memory diagnostics under the same method, with zero forwarding disk-write
bytes measured during each load phase. The short idle sample counts CPU ticks;
its 0.0/0.4% variation is not evidence of an idle-CPU optimization.

Three separate short control windows with that rebuilt binary all passed
case cleanup and CPU audits, but **failed calibration**:

| Gated metric | 1-flow spread | Limit | 8-flow spread | Limit |
|---|---:|---:|---:|---:|
| Throughput | 1.995% | 1.6% | 0.327% | 0.8% |
| Loss-aware p99 | 17.625% | 3.2% | 11.290% | 5.9% |

Evidence: `/home/claude/j324/evidence/calibration-built/spread.json`, raw rows
under `calibration-built-control-{a,b,c}`, and their post-scope restore receipts.
The runner's summary invocation had a renamed-file typo; running the unchanged
`lib/calibration_spread.py` on the completed rows wrote the report above and
returned 1. No timing sample was rerun or discarded to repair that typo.

The earlier reused-binary calibration also failed (1-flow p99 11.575%,
8-flow throughput 2.186%); its first case additionally observed an unrelated
process in the machine diff. Those artifacts remain in `calibration/` and
`calibration-control-{a,b,c}`. No candidate performance acceptance is enabled.
The implementation and memory diagnostics can proceed, but neither
throughput/p99 non-regression nor a CPU win can be claimed from this setup.

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

## Candidate correctness checkpoint

The production changes are split into two atomic commits: `96239d4` releases
blocked-packet deque storage after drain/reset; `77fcd66` introduces the smaller
class in the existing shared pool and uses it in the UDP and Linux TUN copying
paths. Both are pushed to both fork remotes. They are experimental and have no
D348 performance acceptance yet.

The baseline regression run compiled successfully, then failed the two queue
capacity assertions (256 versus zero) and the ordinary-datagram backing-size
assertion (above 2048 bytes). Artifacts on compute01:
`/home/claude/j324-evidence/valid-red-handshake_queue.log` and
`valid-red-mtu_datagrams_use_small_pool.log`. Earlier compile-failing attempts
are preserved separately and are not counted as failing-test evidence.

The single aarch64 batch used `CARGO_INCREMENTAL=0`, three build jobs and the
`env` runner. The queue-only library suite reported 138 passed, zero failed,
seven ignored; the complete candidate reported 142 passed, zero failed,
seven ignored. Integration, CLI and documentation tests passed; all-target
ring clippy completed successfully. Verbatim batch markers:

```text
J324_ARM_QUEUE_CHECKS_EXIT=0
J324_ARM_CHECKS_EXIT=0
J324_ARM_EXIT=0
```

Artifact: dev-02 `/home/claude/j324-evidence/arm-checks.log`, copied to control
`/home/kayg/.cache/codex-scratch/j324/evidence/arm-checks.log`. The batch trap
removed its own target directory. x86 checks, same-build disk comparison,
candidate RSS and allocator-bin diagnostics remain pending.

## Kernel peer-slab diagnostic

A fresh same-protocol kernel run exposed the dedicated `wg_peer` slab: objects
are 1,552 bytes, 21 per eight-page slab. Host-wide reserved slab pages were
unchanged across idle, load and recovery at each scale:

| Peers/endpoint | Reported active objects | Total objects | Slabs | Reserved MiB |
|---|---:|---:|---:|---:|
| 1 | 253 | 378 | 18 | 0.5625 |
| 100 | 399 | 399 | 19 | 0.59375 |
| 1,000 | 2,205 | 2,205 | 105 | 3.28125 |

These are host-wide allocator counts, including pre-existing objects and
cached/free capacity. They are not exact live-peer counts or total kernel
WireGuard memory. Session, allowed-IP, socket and packet allocations remain
outside this dedicated slab. The 1,552-byte structure is therefore only one
component of the kernel memory comparison; no kernel-memory win is claimed.

Artifact: perf VM `/home/claude/j324/evidence/kernel-slab/kernel/mesh-kernel-plain/slab-*.txt`;
console `kernel-slab-console.log` reports exit 0, 129.058 seconds, restored host
placement, and 5 stolen jiffies of 76,999 host-wide. Case audits/machine diff
remain alongside the raw rows. `kernel-slab-overlay.patch` adds the snapshot
to the scale overlay; it does not change the traffic or placement protocol.
The separate inventory log `kernel-inventory.log` records module and slab
identity, also under `perf-run` (exit 0).
