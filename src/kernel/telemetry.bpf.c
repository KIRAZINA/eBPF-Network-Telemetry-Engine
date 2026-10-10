/* SPDX-License-Identifier: GPL-2.0-only */
/* telemetry.bpf.c — XDP + syscall-tracepoint telemetry probes.
 *
 * Build (driven by src/kernel/CMakeLists.txt; do not invoke gcc/ld directly):
 *   clang -target bpf -O2 -g -nostdinc -ffreestanding \
 *     -I src/kernel -I include -I /usr/include \
 *     -D__TARGET_ARCH_x86 [-DHAVE_VMLINUX_H=1 | -DTELEMETRY_NO_VMLINUX_H=1] \
 *     -c src/kernel/telemetry.bpf.c -o telemetry.bpf.o
 *
 * Emits `struct telemetry_event` (include/event_types.h) into the shared
 * BPF_MAP_TYPE_RINGBUF `events`, consumed zero-copy by the C++20 daemon.
 *
 * Verifier discipline: bounded pointer arithmetic with an explicit
 * data_end check before EVERY header dereference, IHL/DOFF validation,
 * no unbounded loops, all helpers __always_inline.
 */

#if defined(HAVE_VMLINUX_H)
#include <vmlinux.h>
#else
#include "vmlinux_compat.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "../../include/event_types.h"

char _license[] SEC("license") = "GPL";

/* BPF_ANY (map update flag) comes from linux/bpf.h, which freestanding
 * -nostdinc builds may not pull in; default matches the UAPI value. */
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

/* ------------------------------------------------------------------ maps */

/* Primary data channel: 256 pages x 4 KiB = 1 MiB ring. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} events SEC(".maps");

/* Active flow / connection tracking. LRU eviction prevents memory exhaustion
 * under DDoS / high-load conditions. */
struct flow_key {
    __u32 saddr;   /* IPv4, network byte order */
    __u32 daddr;   /* IPv4, network byte order */
    __u16 sport;   /* network byte order */
    __u16 dport;   /* network byte order */
    __u8 proto;    /* IPPROTO_TCP / IPPROTO_UDP */
    __u8 _pad[3];  /* explicit padding: key size 16 bytes */
};

struct flow_state {
    __u64 last_seen_ns;
    __u64 syn_count; /* SYN-only packets seen for this flow */
    __u64 pkt_count; /* total packets seen for this flow */
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_track SEC(".maps");

/* --------------------------------------------------------------- constants */

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Flows with more than this many SYN-only packets are flagged anomalous.
 * The user-space sliding-window engine owns the production threshold;
 * this in-kernel check provides an early, fail-open hint. */
#define SYN_FLOOD_HINT_THRESHOLD 64ULL

/* ------------------------------------------------------------- helpers */

static __always_inline struct telemetry_event *events_reserve(void)
{
    return (struct telemetry_event *)bpf_ringbuf_reserve(
        &events, sizeof(struct telemetry_event), 0);
}

/* Tracepoint-context identity: PID/TGID + UID/GID + comm. */
static __always_inline void fill_trace_identity(struct telemetry_event *e,
                                                __u32 type)
{
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = type;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32); /* TGID */
    e->uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFFULL);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* XDP-context record: no owning task exists in the RX path, so identity
 * fields stay zero and the 5-tuple carries the signal. */
static __always_inline void fill_xdp_record(struct telemetry_event *e,
                                            __u32 type, __u32 saddr,
                                            __u32 daddr, __u16 sport,
                                            __u16 dport)
{
    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = type;
    e->src_ip = saddr;
    e->dst_ip = daddr;
    e->src_port = sport;
    e->dst_port = dport;
}

/* ------------------------------------------------------------- XDP prog */

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Ethernet --- */
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; /* IPv4 only in this probe */

    /* --- IPv4 (fixed 20 B part first) --- */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->version != 4)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS; /* malformed */

    /* Full IP header (IHL is in 32-bit words) must be in-bounds. */
    __u32 ip_hdr_len = (__u32)ip->ihl * 4U;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    /* Skip fragmented packets for L4 parsing (fail open). */
    __u16 frag = bpf_ntohs(ip->frag_off);
    int is_frag = (frag & 0x1FFFU) != 0 || (frag & 0x2000U) != 0;
    if (is_frag)
        return XDP_PASS;

    __u8 proto = ip->protocol;
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    void *l4 = (void *)ip + ip_hdr_len;
    __u16 sport = 0, dport = 0;
    int syn_only = 0;

    if (proto == IPPROTO_TCP) {
        /* Fixed TCP header must fit. */
        if (l4 + sizeof(struct tcphdr) > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (struct tcphdr *)l4;
        if (tcp->doff < 5)
            return XDP_PASS; /* malformed */
        /* Full TCP header incl. options must fit. */
        __u32 tcp_hdr_len = (__u32)tcp->doff * 4U;
        if (l4 + tcp_hdr_len > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
        syn_only = tcp->syn && !tcp->ack;
    } else {
        if (l4 + sizeof(struct udphdr) > data_end)
            return XDP_PASS;
        struct udphdr *udp = (struct udphdr *)l4;
        sport = udp->source;
        dport = udp->dest;
        /* UDP carries no SYN signal: update flow state silently below. */
    }

    /* --- Flow tracking (LRU: safe under flood) --- */
    struct flow_key key = {};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.sport = sport;
    key.dport = dport;
    key.proto = proto;

    struct flow_state *st = (struct flow_state *)bpf_map_lookup_elem(
        &flow_track, &key);
    struct flow_state fresh = {};
    __u64 now = bpf_ktime_get_ns();
    if (st) {
        st->last_seen_ns = now;
        st->pkt_count += 1;
        if (syn_only)
            st->syn_count += 1;
    } else {
        fresh.last_seen_ns = now;
        fresh.pkt_count = 1;
        fresh.syn_count = syn_only ? 1 : 0;
        bpf_map_update_elem(&flow_track, &key, &fresh, BPF_ANY);
        st = &fresh;
    }

    /* --- Event policy (fail open, low volume) ---
     * Emit only SYN-only TCP packets (flood candidates). A SYN count past
     * the hint threshold is tagged ANOMALY, otherwise PACKET_DROP-shaped
     * telemetry carrying the 5-tuple for the user-space rate engine.
     * Pure ACK/data/UDP traffic updates flow_track but emits nothing. */
    if (!syn_only)
        return XDP_PASS;

    __u32 type = (st->syn_count >= SYN_FLOOD_HINT_THRESHOLD)
                     ? EVENT_ANOMALY
                     : EVENT_PACKET_DROP;

    struct telemetry_event *e = events_reserve();
    if (!e)
        return XDP_PASS; /* ring full: fail open, packet continues */
    fill_xdp_record(e, type, ip->saddr, ip->daddr, sport, dport);
    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

/* --------------------------------- tracepoint: sys_enter_connect */

SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct telemetry_event *e = events_reserve();
    if (!e)
        return 0;
    fill_trace_identity(e, EVENT_CONN_INIT);
    /* Best-effort sockaddr family peek (failure leaves fields zeroed).
     * args[1] = struct sockaddr __user *uservaddr on sys_enter_connect. */
    unsigned long uservaddr = 0;
    /* Direct ctx->args access is verifier-safe for raw tracepoints;
     * BPF_CORE_READ keeps it CO-RE-portable across kernel versions. */
    uservaddr = BPF_CORE_READ(ctx, args[1]);
    if (uservaddr) {
        __u16 family = 0;
        if (bpf_probe_read_user(&family, sizeof(family),
                                (const void *)uservaddr) == 0) {
            /* Stored in src_port as a compact hint; full 5-tuple
             * correlation happens in user space. */
            e->src_port = family;
        }
    }
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* --------------------------------- tracepoint: sys_enter_execve */

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    (void)ctx;
    struct telemetry_event *e = events_reserve();
    if (!e)
        return 0;
    fill_trace_identity(e, EVENT_CONN_INIT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
