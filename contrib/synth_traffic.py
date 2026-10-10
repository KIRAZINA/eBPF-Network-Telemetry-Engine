#!/usr/bin/env python3
"""synth_traffic.py — synthetic traffic generator for integration testing.

Sends hand-crafted TCP SYN packets (raw sockets, requires root/CAP_NET_RAW)
and a TCP-connect port scan (plain sockets, no privileges) at a target host,
so the XDP probe, sliding-window engine, and Prometheus counters can be
exercised end to end:

    sudo python3 contrib/synth_traffic.py --target 127.0.0.1 \\
        --syn-count 200 --ports 80,443,8000-8010 --verify

With --verify (default on), the script scrapes http://<target>:9090/metrics
before and after and reports the deltas of telemetry_packets_total and
telemetry_anomalies_detected_total.

--dry-run builds the packets and prints them without sending (no root needed).
Requires only the Python standard library. Linux only for the SYN path.
"""

import argparse
import random
import socket
import struct
import sys
import time
import urllib.request

METRICS_PATH = "/metrics"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_syn(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int) -> bytes:
    # --- IPv4 header (no options) ---
    ver_ihl, tos = 0x45, 0
    total_len = 20 + 20
    ident, flags_frag = random.randint(0, 65535), 0x4000  # DF
    ttl, proto = 64, socket.IPPROTO_TCP
    ip = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total_len, ident,
                     flags_frag, ttl, proto, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    # --- TCP header (SYN, no options) ---
    ack, doff_flags = 0, (5 << 12) | 0x02  # data offset 5, SYN
    window, urg = 64240, 0
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                      doff_flags, window, 0, urg)
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) +
              struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp)) + tcp)
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo)) + tcp[18:]
    return ip + tcp


def parse_ports(spec: str) -> list:
    ports: list = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return sorted(set(p for p in ports if 1 <= p <= 65535))


def scrape_metrics(host: str, port: int) -> dict:
    url = "http://%s:%d%s" % (host, port, METRICS_PATH)
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - report, don't crash
        print("metrics scrape failed (%s): %s" % (url, exc))
        return {}
    vals = {}
    for line in body.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        try:
            name, val = line.rsplit(" ", 1)
            vals[name] = float(val)
        except ValueError:
            continue
    return vals


def send_syns(args, target: str) -> int:
    if sys.platform != "linux" and not args.dry_run:
        print("SYN path requires Linux raw sockets; use --dry-run here.")
        return 0
    sock = None
    if not args.dry_run:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            print("ERROR: raw sockets need root (or CAP_NET_RAW). "
                  "Re-run with sudo, or use --dry-run.")
            return 0
    src = args.source_ip or target  # loopback default: self-directed SYNs
    sent = 0
    for i in range(args.syn_count):
        sport = random.randint(1024, 65535)
        pkt = build_syn(src, target, sport, args.syn_port,
                        random.randint(0, 2 ** 32 - 1))
        if args.dry_run:
            if i == 0:
                print("dry-run: %d byte SYN %s:%d -> %s:%d (first packet)" %
                      (len(pkt), src, sport, target, args.syn_port))
            sent += 1
            continue
        try:
            assert sock is not None
            sock.sendto(pkt, (target, 0))
            sent += 1
        except OSError as exc:
            print("sendto failed: %s" % exc)
            break
        if args.rate > 0 and (i + 1) % args.rate == 0:
            time.sleep(1.0)
    if sock is not None:
        sock.close()
    return sent


def run_port_scan(target: str, ports: list) -> dict:
    results = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            rc = s.connect_ex((target, p))
            results[p] = "open" if rc == 0 else "closed"
        except OSError:
            results[p] = "error"
        finally:
            s.close()
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="127.0.0.1",
                    help="destination host (default 127.0.0.1)")
    ap.add_argument("--syn-count", type=int, default=200,
                    help="number of SYN packets to send (default 200)")
    ap.add_argument("--syn-port", type=int, default=80,
                    help="destination port for SYNs (default 80)")
    ap.add_argument("--ports", default="80,443,8000-8010",
                    help="ports for the connect scan (default %(default)s)")
    ap.add_argument("--rate", type=int, default=0,
                    help="packets/sec throttle, 0 = unthrottled")
    ap.add_argument("--source-ip", default="",
                    help="spoofed source IP (default: target itself)")
    ap.add_argument("--metrics-port", type=int, default=9090,
                    help="daemon metrics port for --verify")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip before/after metrics scrape")
    ap.add_argument("--dry-run", action="store_true",
                    help="build packets without sending (no root needed)")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    before = {} if args.no_verify else scrape_metrics(args.target,
                                                      args.metrics_port)

    print("== SYN burst: %d packets -> %s:%d ==" %
          (args.syn_count, args.target, args.syn_port))
    n_syn = send_syns(args, args.target)
    print("sent %d/%d SYN packets" % (n_syn, args.syn_count))

    print("== TCP connect scan: %d ports on %s ==" % (len(ports), args.target))
    results = run_port_scan(args.target, ports)
    n_open = sum(1 for v in results.values() if v == "open")
    print("scan complete: %d open, %d closed" %
          (n_open, len(results) - n_open))

    if not args.no_verify:
        time.sleep(2.0)  # let the daemon poll + triage
        after = scrape_metrics(args.target, args.metrics_port)
        print("== metrics delta ==")
        for key in ("telemetry_packets_total{protocol=\"tcp\",action=\"passed\"}",
                    "telemetry_packets_dropped_total{reason=\"syn_flood\"}",
                    "telemetry_anomalies_detected_total{type=\"syn_flood\"}",
                    "telemetry_anomalies_detected_total{type=\"port_scan\"}"):
            d = after.get(key, 0.0) - before.get(key, 0.0)
            print("  %-60s %+g" % (key, d))
    return 0


if __name__ == "__main__":
    sys.exit(main())
