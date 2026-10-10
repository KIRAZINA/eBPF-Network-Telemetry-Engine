# CI/CD Pipeline — eBPF Network Telemetry Engine

Workflow: `.github/workflows/ci.yml` (GitHub Actions). Static config: `.clang-tidy`.

## Stage map

| # | Job | Gate | Runs on |
|---|---|---|---|
| 1 | `build-and-test` | CMake Release + `-Werror` build, full CTest (26 tests), `[stress],[perf]` binary gate | every push/PR, weekly schedule |
| 2 | `sanitizers` | Debug + `ENABLE_ASAN=ON` (ASan/UBSan) build + full CTest, zero findings | every push/PR |
| 3 | `clang-tidy` | `.clang-tidy` checks on `src/daemon/*.cpp` with `--warnings-as-errors='*'` | every push/PR |
| 4 | `bpf-verify` | ELF/eBPF type + `license`/`.maps`/prog sections via `llvm-readelf`, then **real `bpftool prog load`** (kernel verifier) with pinned-path cleanup | every push/PR, after job 1 |
| 5 | `package` | Version (`git describe --tags`, fallback `0.1.0+sha`), tarball (daemon + `.bpf.o` + service + runbook) + SHA256; GitHub Release on `v*` tags | after jobs 1–4 |
| 6 | `docker` | Build image from `deploy/daemon/Dockerfile`; push immutable tags to GHCR **on `v*` tags only** | after job 1 |

Concurrency cancels superseded runs per ref. Default `GITHUB_TOKEN` permissions are `contents:read`; `package` escalates to `contents:write` (releases) and `docker` to `packages:write` (GHCR push) at job scope only.

## Runner requirements

- Linux x86_64 with BTF-enabled kernel 5.8+ — the `bpf-verify` job loads a program, which executes the in-kernel verifier. GitHub-hosted `ubuntu-24.04` qualifies.
- Container jobs install the runbook toolchain (`build-essential cmake ninja-build pkg-config git ca-certificates clang llvm libbpf-dev libelf-dev zlib1g-dev linux-tools-common linux-tools-generic linux-headers-generic`). Notes: `bpftool` is virtual on noble — the workflow installs the real providers; `ca-certificates` is mandatory, otherwise FetchContent's `git clone https://…` fails TLS verification (`CAfile: none`).

## Releasing

```bash
git tag -a v0.2.0 -m "SYN-flood triage, metrics exporter"
git push origin v0.2.0
```

A tag push runs the full pipeline, then publishes: versioned tarball + checksums as a GitHub Release, and `ghcr.io/<owner>/<repo>:0.2.0` (+ `latest`, + short-SHA) images.

## Local equivalents (no Actions runner needed)

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
./build/bin/telemetry_tests "[stress],[perf]" -s
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON && cmake --build build-asan -j && ctest --test-dir build-asan
clang-tidy src/daemon/*.cpp -p build --warnings-as-errors='*'
sudo bpftool prog load build/src/kernel/telemetry.bpf.o /sys/fs/bpf/ci_verify autoattach && sudo rm /sys/fs/bpf/ci_verify
python engine_manager.py   # end-to-end equivalent on WSL2/Linux
```

## Secrets

None beyond the automatic `GITHUB_TOKEN`. No registry credentials are stored — GHCR auth uses the token at push time on tag events only.
