# Deployment Runbook — eBPF Network Telemetry & Security Engine

**Applies to:** `ebpf-telemetry-daemon` + `telemetry.bpf.o` (XDP / tracepoint probes)
**Default metrics endpoint:** `http://<host>:9090/metrics` · **Health:** `http://<host>:9090/healthz`
**CLI:** `ebpf-telemetry-daemon [bpf_object] [ifindex] [metrics_port]`

---

## 1. System Prerequisites & Kernel Requirements

### 1.1 Kernel version

Minimum **Linux 5.8** (first kernel with `BPF_MAP_TYPE_RINGBUF` and full BTF-powered CO-RE).
Recommended: latest stable 6.x with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).

```bash
uname -r                      # expect 5.8+
# BTF availability (required for vmlinux.h generation and CO-RE loads):
ls -l /sys/kernel/btf/vmlinux
# Kernel BTF config flag (on most distros):
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

If `/sys/kernel/btf/vmlinux` is absent, see §5.2.

### 1.2 Required packages

Debian / Ubuntu:

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build pkg-config git curl \
  clang llvm \
  libbpf-dev libelf-dev zlib1g-dev \
  bpftool \
  linux-headers-$(uname -r) \
  prometheus-node-exporter
```

RHEL / Fedora equivalents:

```bash
sudo dnf install -y \
  gcc-c++ cmake ninja-build pkgconfig git curl \
  clang llvm \
  libbpf-devel elfutils-libelf-devel zlib-devel \
  bpftool \
  kernel-headers kernel-devel
```

### 1.3 Capability prerequisites

The daemon must run with `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_SYS_ADMIN`
(on kernels < 5.8 `CAP_BPF` does not exist — `CAP_SYS_ADMIN` covers it).
XDP attach additionally requires the target interface index (`ip link`).

```bash
ip -o link show               # note IFINDEX of the monitored NIC
id                            # service account for §3 (recommend dedicated user)
```

---

## 2. Compilation & Packaging

### 2.1 Release build

```bash
git clone <repo-url> ebpf-telemetry && cd ebpf-telemetry

# vmlinux.h is auto-generated at configure time from host BTF when
# bpftool + /sys/kernel/btf/vmlinux exist; otherwise generate manually:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"

# Artifacts:
#   build/bin/ebpf-telemetry-daemon   (user-space daemon)
#   build/src/kernel/telemetry.bpf.o  (eBPF bytecode)
ctest --test-dir build --output-on-failure
```

### 2.2 Install / package layout

```bash
sudo cmake --install build --prefix /usr/local
# /usr/local/bin/ebpf-telemetry-daemon
# /usr/local/share/ebpf-telemetry/bpf/telemetry.bpf.o

# Optional tarball for fleet rollout:
tar -C /usr/local -czf ebpf-telemetry-release.tar.gz \
  bin/ebpf-telemetry-daemon share/ebpf-telemetry/bpf/telemetry.bpf.o
```

### 2.3 Sanitizer build (staging / QA only — never production)

```bash
cmake -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON
cmake --build build-asan -j"$(nproc)"
ctest --test-dir build-asan --output-on-failure
```

`ENABLE_ASAN=ON` compiles user-space targets with
`-fsanitize=address,undefined -fno-omit-frame-pointer` and links the runtimes.
Gate promotion on zero ASan/UBSan findings.

### 2.4 Smoke test before installing the service

```bash
IFINDEX=$(ip -o link show eth0 | awk -F': ' '{print $1}')
sudo ./build/bin/ebpf-telemetry-daemon \
  ./build/src/kernel/telemetry.bpf.o "$IFINDEX" 9090 &
sleep 3
curl -s http://localhost:9090/healthz
curl -s http://localhost:9090/metrics | head -30
kill %1
```

### 2.5 Synthetic traffic integration test

`contrib/synth_traffic.py` (stdlib only, Linux) sends hand-crafted SYN bursts
plus a TCP-connect port scan and reports before/after metric deltas:

```bash
# Syntax / packet-build check only (no root required):
python3 contrib/synth_traffic.py --help
python3 contrib/synth_traffic.py --dry-run --syn-count 10

# Live exercise against a running daemon (requires root for raw sockets):
sudo ./build/bin/ebpf-telemetry-daemon \
  ./build/src/kernel/telemetry.bpf.o "$IFINDEX" 9090 &
sleep 2
sudo python3 contrib/synth_traffic.py --target 127.0.0.1 \
  --syn-count 200 --ports 80,443,8000-8010
# Expect positive deltas on telemetry_packets_total and
# telemetry_anomalies_detected_total{type="syn_flood"|"port_scan"}.
kill %1
```

---

## 3. Systemd Service Integration

### 3.1 `ebpf-telemetry.service`

Ship-ready unit file: `contrib/ebpf-telemetry.service`. Install it with:

```bash
sudo cp contrib/ebpf-telemetry.service /etc/systemd/system/
```

Adjust `IFINDEX` (target NIC) and paths to match §2.2. Contents:

```ini
[Unit]
Description=eBPF Network Telemetry & Security Engine
Documentation=https://example.com/ebpf-telemetry/docs/Deployment-Runbook.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ebpf-telemetry
Group=ebpf-telemetry
ExecStart=/usr/local/bin/ebpf-telemetry-daemon \
  /usr/local/share/ebpf-telemetry/bpf/telemetry.bpf.o \
  ${IFINDEX} 9090
Environment=IFINDEX=2
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=300
StartLimitBurst=5

# Privileges: BPF map/prog management + XDP attach + tracepoints.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_BPF
NoNewPrivileges=false

# Filesystem sandboxing.
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

# Logging to journald.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ebpf-telemetry

[Install]
WantedBy=multi-user.target
```

> `NoNewPrivileges=false` is intentional: ambient capabilities are dropped
> otherwise. If the fleet standard mandates `NoNewPrivileges=true`, use
> `CAP_SYS_ADMIN`-equipped file capabilities instead:
> `setcap cap_net_admin,cap_sys_admin,cap_bpf+eip /usr/local/bin/ebpf-telemetry-daemon`
> and drop the `AmbientCapabilities=` line.

### 3.2 Enable and start

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ebpf-telemetry
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-telemetry.service
systemctl status ebpf-telemetry.service --no-pager
journalctl -u ebpf-telemetry.service -f
```

---

## 4. Prometheus & Grafana Observability Setup

### 4.1 Daemon metrics reference

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `telemetry_packets_total` | counter | `protocol="tcp"`, `action="passed"` | XDP-seen packets passed (fail-open telemetry) |
| `telemetry_packets_dropped_total` | counter | `reason="syn_flood"` | In-kernel SYN-flood hints |
| `telemetry_anomalies_detected_total` | counter | `type="syn_flood" \| "port_scan" \| "suspicious_process"` | Detector verdicts |
| `telemetry_active_flows` | gauge | — | Currently tracked flows |
| `telemetry_conn_events_total` | counter | — | Tracepoint connect/exec correlations |
| `telemetry_ring_consumed_total` / `telemetry_ring_errors_total` | counter | — | Ring-buffer health |

> **Metric standardization (release close-out):** the canonical detector
> counter is `telemetry_anomalies_detected_total{type=...}` with
> `type ∈ {syn_flood, port_scan, suspicious_process}`, exactly as rendered by
> `src/daemon/metrics_exporter.cpp`, asserted in
> `tests/test_metrics_exporter.cpp` / `test_pipeline_integration.cpp`, and
> scraped in §4.2–§4.4. The shorter `telemetry_anomalies_total` spelling from
> the original `Plan.md` sketch is retired — dashboards and alerts must use
> the `_detected` name. (`Plan.md` Phase 5 carries the same note.)

### 4.2 Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ebpf-telemetry
    scrape_interval: 15s
    scrape_timeout: 10s
    static_configs:
      - targets: ['telemetry-01:9090', 'telemetry-02:9090']
```

Reload and verify target health: Prometheus UI → Status → Targets (`up == 1`).

### 4.3 Key queries (Grafana / PromQL)

```promql
# Ingest rate by outcome
sum(rate(telemetry_packets_total[5m]))
sum(rate(telemetry_packets_dropped_total[5m]))

# Drop ratio (SYN-flood pressure)
sum(rate(telemetry_packets_dropped_total[5m]))
/
(sum(rate(telemetry_packets_total[5m])) + sum(rate(telemetry_packets_dropped_total[5m])))

# Anomaly rate by detector type
sum by (type) (rate(telemetry_anomalies_detected_total[5m]))

# Flow-table pressure
telemetry_active_flows

# Pipeline health (expect errors == 0)
rate(telemetry_ring_errors_total[5m])
```

Suggested Grafana panels: ingest/drop timeseries, anomaly-by-type stacked graph,
`telemetry_active_flows` gauge with 80 % capacity annotation, ring-error alert
singlestat.

### 4.4 Alerting rules

```yaml
# /etc/prometheus/rules/ebpf-telemetry.yml
groups:
  - name: ebpf-telemetry
    interval: 30s
    rules:
      - alert: SynFloodPressure
        expr: |
          sum(rate(telemetry_packets_dropped_total{reason="syn_flood"}[5m])) > 50
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "SYN-flood drop rate high on {{ $labels.instance }}"
          description: "Dropped {{ $value | humanize }} pkts/s over 5m window."

      - alert: PortScanDetected
        expr: |
          sum(rate(telemetry_anomalies_detected_total{type="port_scan"}[10m])) > 0
        for: 1m
        labels: { severity: warning }
        annotations:
          summary: "Port-scan anomaly on {{ $labels.instance }}"

      - alert: AnomalyRateSpike
        expr: |
          sum(rate(telemetry_anomalies_detected_total[5m])) > 10
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Anomaly verdict spike on {{ $labels.instance }}"

      - alert: TelemetryPipelineDown
        expr: up{job="ebpf-telemetry"} == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Telemetry target {{ $labels.instance }} down"

      - alert: RingBufferErrors
        expr: sum(rate(telemetry_ring_errors_total[5m])) > 0
        for: 2m
        labels: { severity: warning }
        annotations:
          summary: "Ring-buffer errors on {{ $labels.instance }}"
```

Tune thresholds per baseline (start from §4.3 dashboards, then set alerts at
p99 + margin). Route critical alerts to paging, warnings to the SOC queue.

---

## 5. Operational Troubleshooting & Health Verification

### 5.1 Health verification

```bash
systemctl is-active ebpf-telemetry.service
curl -s http://localhost:9090/healthz          # expect: ok
curl -s http://localhost:9090/metrics | head -40
journalctl -u ebpf-telemetry.service --since "15 min ago" --no-pager
# BPF objects actually loaded:
sudo bpftool prog show | grep -i telemetry
sudo bpftool map show | grep -i -E "events|flow_track"
```

### 5.2 Missing BTF support

Symptoms: configure warns `BTF file /sys/kernel/btf/vmlinux not found`;
daemon logs load failures; CO-RE relocations rejected.

```bash
ls /sys/kernel/btf/vmlinux || echo "NO BTF"
```

Resolutions (in order):

1. Boot a BTF-enabled kernel (`CONFIG_DEBUG_INFO_BTF=y`; Ubuntu 20.04+,
   RHEL 8.4+ / Fedora 31+ ship it).
2. Regenerate `vmlinux.h` on a BTF host and ship it with the package:
   `bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h`,
   then rebuild (kernel CMake defines `HAVE_VMLINUX_H=1` automatically).
3. Without BTF the build falls back to stub types (`TELEMETRY_NO_VMLINUX_H`)
   for parsing only — loads will fail; do not deploy this configuration.

### 5.3 Insufficient capabilities

Symptoms: `EPERM` on load/attach, `bpf_object__load` / `attach_xdp` errors in
journald, exit-code loops with `Restart=on-failure`.

```bash
journalctl -u ebpf-telemetry.service -p err --no-pager | tail -20
systemctl show ebpf-telemetry.service -p CapabilityBoundingSet,AmbientCapabilities
```

Resolutions: confirm §3 sandbox lines are present, `NoNewPrivileges=false`
(or file capabilities per the note in §3.1), service user has no seccomp
override stripping `bpf(2)`, and the kernel is ≥ 5.8 for `CAP_BPF`
(else rely on `CAP_SYS_ADMIN`).

### 5.4 Verifier rejection

Symptoms: `bpf_object__load` fails; `dmesg`/`journalctl -k` shows
`verifier ... rejected` with an instruction trace.

```bash
sudo dmesg -T | tail -50 | grep -i -A5 verifier
```

Resolutions:

1. Confirm the shipped `.bpf.o` matches the running kernel's headers —
   rebuild `vmlinux.h` on the target kernel family (§5.2.2) and recompile.
2. Check the object was built with `clang -target bpf -O2 -g` via the
   kernel CMake target (never hand-invoked gcc) — `file telemetry.bpf.o`
   must report BPF.
3. Bisect recent BPF C changes; every header dereference requires a prior
   `data_end` bounds check (see `src/kernel/telemetry.bpf.c`).
4. As a stopgap, run the daemon degraded (invalid map fd → pipeline idles,
   metrics stay up) while rolling back to the last known-good `.bpf.o`.

### 5.5 Metrics endpoint down but process alive

```bash
ss -ltnp | grep 9090
curl -sv http://localhost:9090/healthz
```

Causes: port conflict (change argv[3]), local firewall, or exporter bind
failure (logged at startup as `metrics exporter unavailable`). The daemon
continues telemetry without exposition — fix the port and
`systemctl restart ebpf-telemetry.service`.

### 5.6 Ring-buffer errors climbing

`rate(telemetry_ring_errors_total[5m]) > 0` or consumer queue drops rising:
the analytics thread is slower than ingest. Scale vertically (faster core for
the daemon), raise `EventQueue` capacity, or lower XDP emission (raise the
in-kernel `SYN_FLOOD_HINT_THRESHOLD`). Sustained drops + high
`telemetry_active_flows` indicate genuine flood — treat as an incident, not a
bug.

---

## Appendix A — Rollback

```bash
sudo systemctl stop ebpf-telemetry.service
# restore previous tarball from §2.2, then:
sudo tar -C /usr/local -xzf /opt/artifacts/ebpf-telemetry-prev.tar.gz
sudo systemctl start ebpf-telemetry.service
curl -s http://localhost:9090/healthz
```

## Appendix B — Upgrade checklist

1. Build + `ctest` green (Release and ASan jobs).
2. Stage on one canary host; watch §4.3 dashboards for 30 min.
3. Promote fleet-wide; confirm `up{job="ebpf-telemetry"} == 1` for all targets.
4. Verify no `SynFloodPressure` / `RingBufferErrors` alerts fire spuriously.
