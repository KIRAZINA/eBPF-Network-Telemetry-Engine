#ifndef EVENT_TYPES_H
#define EVENT_TYPES_H

/* event_types.h — strictly layout-aligned shared ABI (kernel C + C++20).
 *
 * Rules:
 *  - Fixed-width integers only, field order frozen (ABI v1).
 *  - 8-byte alignment: alignas(8) in C++20, __attribute__((aligned(8))) in C.
 *  - Total size exactly 48 bytes; no implicit padding beyond natural layout.
 *  - C++ side enforces sizeof / alignof / offsetof via static_assert.
 *  - C11 side enforces sizeof via _Static_assert where available.
 */

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>

/* NOTE: kernel-style __u64/__u32/... aliases are intentionally NOT provided
 * here. They collide with <linux/types.h> whenever a translation unit also
 * includes libbpf/UAPI headers (e.g. ring_buffer_consumer.cpp). The struct
 * below uses std::uintXX_t directly — identical layout, no namespace clash.
 * The BPF C branch below keeps using __uXX from <linux/types.h>. */

#define TASK_COMM_LEN 16

enum event_type : std::uint32_t {
    EVENT_PACKET_DROP = 1,
    EVENT_CONN_INIT = 2,
    EVENT_ANOMALY = 3
};

/* Backward-compatible aliases used by daemon/tests. */
constexpr event_type TELEMETRY_EVENT_PACKET_DROP = EVENT_PACKET_DROP;
constexpr event_type TELEMETRY_EVENT_CONN_INIT = EVENT_CONN_INIT;
constexpr event_type TELEMETRY_EVENT_ANOMALY = EVENT_ANOMALY;
#define TELEMETRY_TASK_COMM_LEN TASK_COMM_LEN
#define TELEMETRY_ABI_VERSION 1

struct alignas(8) telemetry_event {
    std::uint64_t timestamp_ns;   /* bpf_ktime_get_ns() */
    std::uint32_t src_ip;         /* IPv4, network byte order */
    std::uint32_t dst_ip;         /* IPv4, network byte order */
    std::uint16_t src_port;       /* network byte order */
    std::uint16_t dst_port;       /* network byte order */
    std::uint32_t pid;            /* TGID of submitting task */
    std::uint32_t uid;            /* UID of submitting task */
    std::uint32_t event_type;     /* enum event_type */
    char comm[TASK_COMM_LEN];     /* executable name, NUL-terminated */
};

static_assert(sizeof(telemetry_event) == 48,
              "telemetry_event ABI must be exactly 48 bytes");
static_assert(alignof(telemetry_event) == 8,
              "telemetry_event ABI must be 8-byte aligned");
static_assert(offsetof(telemetry_event, timestamp_ns) == 0, "bad offset timestamp_ns");
static_assert(offsetof(telemetry_event, src_ip) == 8, "bad offset src_ip");
static_assert(offsetof(telemetry_event, dst_ip) == 12, "bad offset dst_ip");
static_assert(offsetof(telemetry_event, src_port) == 16, "bad offset src_port");
static_assert(offsetof(telemetry_event, dst_port) == 18, "bad offset dst_port");
static_assert(offsetof(telemetry_event, pid) == 20, "bad offset pid");
static_assert(offsetof(telemetry_event, uid) == 24, "bad offset uid");
static_assert(offsetof(telemetry_event, event_type) == 28, "bad offset event_type");
static_assert(offsetof(telemetry_event, comm) == 32, "bad offset comm");
static_assert(sizeof(telemetry_event::comm) == 16, "comm must be 16 bytes");

#else /* !__cplusplus — kernel C / plain C */

/* vmlinux.h (BTF dump) and vmlinux_compat.h already provide __u64/__u32/...
 * Identical typedef redefinition is legal in C11, but skip the UAPI include
 * outright when either header came first. */
#if !defined(TELEMETRY_COMPAT_TYPES_DEFINED) && !defined(__VMLINUX_H__)
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16
#define TELEMETRY_TASK_COMM_LEN TASK_COMM_LEN
#define TELEMETRY_ABI_VERSION 1

enum event_type {
    EVENT_PACKET_DROP = 1,
    EVENT_CONN_INIT = 2,
    EVENT_ANOMALY = 3
};

/* Aliases for code written against the TELEMETRY_ spelling. */
#define TELEMETRY_EVENT_PACKET_DROP EVENT_PACKET_DROP
#define TELEMETRY_EVENT_CONN_INIT EVENT_CONN_INIT
#define TELEMETRY_EVENT_ANOMALY EVENT_ANOMALY

struct __attribute__((aligned(8))) telemetry_event {
    __u64 timestamp_ns;       /* bpf_ktime_get_ns() */
    __u32 src_ip;             /* IPv4, network byte order */
    __u32 dst_ip;             /* IPv4, network byte order */
    __u16 src_port;           /* network byte order */
    __u16 dst_port;           /* network byte order */
    __u32 pid;                /* TGID of submitting task */
    __u32 uid;                /* UID of submitting task */
    __u32 event_type;         /* enum event_type */
    char comm[TASK_COMM_LEN]; /* executable name, NUL-terminated */
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct telemetry_event) == 48,
               "telemetry_event ABI must be exactly 48 bytes");
_Static_assert(_Alignof(struct telemetry_event) == 8,
               "telemetry_event ABI must be 8-byte aligned");
#endif

#endif /* __cplusplus */

#endif /* EVENT_TYPES_H */
