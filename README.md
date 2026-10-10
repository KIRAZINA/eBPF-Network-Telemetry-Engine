# eBPF Network Telemetry Engine

Production-grade network telemetry and anomaly detection: XDP + syscall-tracepoint
probes in the kernel stream compact binary events through a lock-free ring buffer
into a modern C++20 user-space daemon (RAII libbpf management, zero-copy consumer,
sharded flow tracker, lock-free sliding-window rate estimator, anomaly triage),
exposed via an embedded Prometheus endpoint with Grafana dashboards and alerting.

## Features

- **Kernel probes** (`src/kernel/`): XDP packet path (SYN-flood hints, 5-tuple
  extraction) + `sys_enter_connect` / `sys_enter_execve` tracepoints (PID/UID/comm),
  emitted over `BPF_MAP_TYPE_RINGBUF` with LRU flow tracking.
- **C++20 daemon** (`src/daemon/`): `BpfManager` RAII owner, zero-copy
  `RingBufferConsumer` (`std::span<const std::byte>`), `std::jthread` workers,
  `ConnectionTracker` (32 shards), `SlidingWindowCounter` (lock-free, 100 ms),
  `AnomalyDetector` (SYN-flood / port-scan / suspicious-process), embedded
  Prometheus exporter (`:9090/metrics`, `/healthz`).
- **Build system**: dual-target CMake 3.22+ (Clang `-target bpf` bytecode +
  strict `-Werror` C++20), auto-generated `vmlinux.h` from host BTF with stub
  fallback, Catch2 suite (26 tests incl. `[stress]`/`[perf]`), ASan/UBSan and
  clang-tidy gates, GitHub Actions CI with a real `bpftool prog load` verifier gate.
- **Deploy**: Docker Compose observability stack (Prometheus + alert rules with
  `promtool` unit tests, provisioned Grafana dashboard), systemd unit, synthetic
  traffic generator, and a WSL-aware `engine_manager.py` bootstrap.

## Architecture

```
kernel:  XDP probe + tracepoints --> RINGBUF(events) + LRU(flow_track)
user:    BpfManager -> RingBufferConsumer -/zero-copy/-> EventQueue
         -> ConnectionTracker + AnomalyDetector -> MetricsExporter :9090
obs:     Prometheus (5s scrape, alerts) + Grafana (provisioned dashboard)
```

## Prerequisites

- Linux kernel **5.8+** with BTF (`/sys/kernel/btf/vmlinux`) for real BPF loads.
- Toolchain: GCC 13+ / Clang 18+, CMake 3.22+, `libbpf-dev`, `libelf-dev`,
  `zlib1g-dev`, `bpftool` (or `linux-tools-common` + `linux-tools-generic`),
  kernel headers. Full per-distro lists: `Deployment-Runbook.md` §1.
- Windows developers: WSL2 Ubuntu + `python engine_manager.py` (auto-detects WSL,
  translates paths, runs the whole pipeline inside Linux).

## Quickstart

```bash
# One-command bootstrap (Linux, or Windows with WSL2):
python engine_manager.py
# -> preflight, cmake Release configure, parallel build, full ctest,
#    then prints the copy-paste sudo command to run the daemon.

# Manual equivalent:
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure

# Sanitizers (staging/QA):
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build build-asan -j && ctest --test-dir build-asan

# Run (needs root for BPF load/XDP):
IFINDEX=$(ip -o link show eth0 | awk -F': ' '{print $1}')
sudo ./build/bin/ebpf-telemetry-daemon ./build/src/kernel/telemetry.bpf.o "$IFINDEX" 9090
curl -s http://localhost:9090/metrics | head -30

# Synthetic load check (root, stdlib only):
sudo python3 contrib/synth_traffic.py --target 127.0.0.1 --syn-count 200 --ports 80,443,8000-8010
```

## Metrics (excerpt)

| Metric | Type | Meaning |
|---|---|---|
| `telemetry_packets_total{protocol="tcp",action="passed"}` | counter | XDP-seen packets passed |
| `telemetry_packets_dropped_total{reason="syn_flood"}` | counter | In-kernel SYN-flood hints |
| `telemetry_anomalies_detected_total{type="…"}` | counter | Detector verdicts (`syn_flood`/`port_scan`/`suspicious_process`) |
| `telemetry_active_flows` | gauge | Tracked flows |
| `telemetry_conn_events_total` | counter | Tracepoint correlations |

## Deploy

```bash
docker compose config                                  # offline validation
IFINDEX=2 docker compose up -d --build                 # Prometheus :9091, Grafana :3000
sudo cp contrib/ebpf-telemetry.service /etc/systemd/system/  # bare-metal alternative
```

## Project layout

```
CMakeLists.txt  cmake/                 # dual-target build, FindLibbpf, strict flags
include/event_types.h                  # 48-byte shared kernel<->userspace ABI
src/kernel/telemetry.bpf.c             # XDP + tracepoint probes
src/daemon/                            # manager, consumer, tracker, detector, metrics
tests/                                 # 7 Catch2 suites (layout/window/ring/tracker/anomaly/metrics/pipeline)
deploy/                                # prometheus rules, grafana, daemon Dockerfile, e2e checks
contrib/                               # systemd unit, synth_traffic.py
.github/workflows/ci.yml  .clang-tidy # build/test/sanitizer/tidy/verifier/release/docker
engine_manager.py                      # WSL-aware bootstrap (preflight->build->test->run hints)
lib/selfheal.py  tools/rdp_connect.py  # self-healing launcher framework + example
```

## Docs

- `Deployment-Runbook.md` — provisioning, systemd, Prometheus/Grafana ops, troubleshooting.
- `docs/ci-cd-pipeline.md` — pipeline stages, gates, releasing (`git tag vX.Y.Z`).
- `Plan.md` — original architecture roadmap and audit baseline.

## License

GNU General Public License v2.0 only — see [`LICENSE`](LICENSE).
Kernel-space BPF programs carry matching `GPL-2.0-only` SPDX headers (a kernel
requirement for the helpers used).
