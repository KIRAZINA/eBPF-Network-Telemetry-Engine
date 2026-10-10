/* vmlinux_compat.h — minimal kernel-type stubs for freestanding BPF builds
 * WITHOUT generated vmlinux.h.
 *
 * Selection logic lives in telemetry.bpf.c:
 *   #if HAVE_VMLINUX_H  ->  #include <vmlinux.h>   (real CO-RE types)
 *   #else               ->  #include "vmlinux_compat.h" (this stub)
 *
 * Generate the real header on a BTF host with:
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
 * The stub exists only to keep `clang -target bpf -nostdinc` parsing green
 * until then; it cannot provide CO-RE relocations at load time.
 */
#ifndef TELEMETRY_VMLINUX_COMPAT_H
#define TELEMETRY_VMLINUX_COMPAT_H

/* Guard against accidental use alongside the real vmlinux.h. */
#ifdef HAVE_VMLINUX_H
#error "vmlinux_compat.h must not be included when HAVE_VMLINUX_H is set; include <vmlinux.h> instead"
#endif

/* Kernel integer types: pull the full UAPI set (__u64/__u32/... plus the
 * SIGNED __s64/__s32 family) from <linux/types.h>, which resolves via
 * -I/usr/include even under -nostdinc (see src/kernel/CMakeLists.txt).
 * Hand-rolled typedefs are deliberately NOT used here: bpf_helper_defs.h
 * needs __s64/__s32/__wsum, and partial stubs break its prototypes. */
#include <linux/types.h>

/* Checksum word type (linux/checksum.h), needed by bpf_helper_defs.h
 * prototypes such as bpf_csum_diff / bpf_csum_update. Matches the kernel:
 * typedef __u32 __wsum. */
typedef __u32 __wsum;

typedef __u16 __be16;
typedef __u32 __be32;

/* BPF map/program-type enum constants (BPF_MAP_TYPE_RINGBUF,
 * BPF_MAP_TYPE_LRU_HASH, struct __sk_buff, ...). Resolves via -I/usr/include
 * even under -nostdinc. Must come AFTER <linux/types.h> above. Brings no
 * conflicting struct definitions (no ethhdr/iphdr/tcphdr/xdp_md here). */
#include <linux/bpf.h>

#define TELEMETRY_COMPAT_TYPES_DEFINED 1

/* NOTE: struct xdp_md is intentionally NOT defined here — it already comes
 * from <linux/bpf.h> below. Defining it twice is a hard error. */

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ihl : 4;
    __u8 version : 4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4;
    __u16 doff : 4;
    __u16 fin : 1;
    __u16 syn : 1;
    __u16 rst : 1;
    __u16 psh : 1;
    __u16 ack : 1;
    __u16 urg : 1;
    __u16 ece : 1;
    __u16 cwr : 1;
    __be16 window;
    __u16 check;
    __u16 urg_ptr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

struct trace_event_raw_sys_enter {
    short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

#endif /* TELEMETRY_VMLINUX_COMPAT_H */
