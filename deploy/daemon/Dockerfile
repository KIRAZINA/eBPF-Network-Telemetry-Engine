# Dockerfile — eBPF telemetry daemon image (multi-stage).
#
# Build:   docker build -f deploy/daemon/Dockerfile -t ebpf-telemetry:latest .
# Run:     via docker-compose.yml (host network + BPF capabilities), or:
#          docker run --rm --network host --cap-add SYS_ADMIN --cap-add NET_ADMIN \
#            --cap-add BPF -v /sys/kernel/debug:/sys/kernel/debug \
#            -v /sys/fs/bpf:/sys/fs/bpf ebpf-telemetry:latest
#
# NOTE on vmlinux.h: the builder has no host BTF, so the BPF object compiles
# against the stub fallback (see src/kernel/vmlinux_compat.h). For production
# CO-RE loads, prefer building on a BTF-enabled host (engine_manager.py) and
# COPY the resulting telemetry.bpf.o over the staged one, or bind-mount it.

FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config clang llvm \
        libbpf-dev libelf-dev zlib1g-dev ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)"

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libbpf1 libelf1 zlib1g curl iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/bin/ebpf-telemetry-daemon /usr/local/bin/ebpf-telemetry-daemon
COPY --from=builder /src/build/src/kernel/telemetry.bpf.o /usr/local/share/ebpf-telemetry/bpf/telemetry.bpf.o
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/ebpf-telemetry-daemon"]
CMD ["/usr/local/share/ebpf-telemetry/bpf/telemetry.bpf.o", "2", "9090"]
