// metrics_exporter.cpp — Prometheus exposition endpoint implementation.

#include "metrics_exporter.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <stop_token>
#include <thread>
#include <utility>

#include "anomaly_detector.hpp"
#include "event_types.h"

#if defined(__linux__) || defined(__APPLE__)
#include <cerrno>
#include <sys/select.h>
#include <sys/socket.h>
// NOLINTNEXTLINE(misc-include-cleaner) — tidy-18 DB gap: this IS the provider
// of timeval (verified: TU builds warning-free without transitive reliance).
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace telemetry {

MetricsExporter::MetricsExporter(std::uint16_t port, std::string bind_addr)
    : port_(port)
    , bind_addr_(std::move(bind_addr))
{
}

MetricsExporter::~MetricsExporter()
{
    stop();
}

void MetricsExporter::inc_packets_passed(std::uint64_t n) noexcept
{
    packets_passed_.fetch_add(n, std::memory_order_relaxed);
}

void MetricsExporter::inc_packets_dropped_syn(std::uint64_t n) noexcept
{
    packets_dropped_syn_.fetch_add(n, std::memory_order_relaxed);
}

void MetricsExporter::inc_conn_events(std::uint64_t n) noexcept
{
    conn_events_.fetch_add(n, std::memory_order_relaxed);
}

void MetricsExporter::inc_anomaly(AnomalyKind kind) noexcept
{
    switch (kind) {
    case AnomalyKind::kSynFlood:
        anomalies_syn_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
        break;
    case AnomalyKind::kPortScan:
        anomalies_scan_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
        break;
    case AnomalyKind::kSuspiciousProcess:
        anomalies_proc_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
        break;
    }
}

void MetricsExporter::set_active_flows(std::uint64_t n) noexcept
{
    active_flows_.store(n, std::memory_order_relaxed);
}

void MetricsExporter::set_ring_stats(std::uint64_t consumed,
                                     std::uint64_t errors) noexcept
{
    ring_consumed_.store(consumed, std::memory_order_relaxed);
    ring_errors_.store(errors, std::memory_order_relaxed);
}

void MetricsExporter::observe_event(const telemetry_event& evt) noexcept
{
    // XDP SYN telemetry is fail-open: PACKET_DROP-shaped records are packets
    // the datapath PASSED while flagging them for the rate engine; ANOMALY
    // records are in-kernel syn_flood hints counted as drops.
    switch (evt.event_type) {
    case EVENT_PACKET_DROP:
        inc_packets_passed();
        break;
    case EVENT_ANOMALY:
        inc_packets_dropped_syn();
        break;
    case EVENT_CONN_INIT:
        inc_conn_events();
        break;
    default:
        break;
    }
}

std::string MetricsExporter::render() const
{
    const auto passed = packets_passed_.load(std::memory_order_relaxed);
    const auto dropped = packets_dropped_syn_.load(std::memory_order_relaxed);
    const auto conns = conn_events_.load(std::memory_order_relaxed);
    const auto syn = anomalies_syn_.load(std::memory_order_relaxed);
    const auto scan = anomalies_scan_.load(std::memory_order_relaxed);
    const auto proc = anomalies_proc_.load(std::memory_order_relaxed);
    const auto flows = active_flows_.load(std::memory_order_relaxed);
    const auto consumed = ring_consumed_.load(std::memory_order_relaxed);
    const auto errors = ring_errors_.load(std::memory_order_relaxed);

    std::string out;
    out.reserve(1024);
    out += "# HELP telemetry_packets_total Packets seen by the XDP probe, by protocol and action.\n";
    out += "# TYPE telemetry_packets_total counter\n";
    out += "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} ";
    out += std::to_string(passed);
    out += "\n";
    out += "# HELP telemetry_packets_dropped_total Packets flagged as drops, by reason.\n";
    out += "# TYPE telemetry_packets_dropped_total counter\n";
    out += "telemetry_packets_dropped_total{reason=\"syn_flood\"} ";
    out += std::to_string(dropped);
    out += "\n";
    out += "# HELP telemetry_anomalies_detected_total Detector verdicts, by type.\n";
    out += "# TYPE telemetry_anomalies_detected_total counter\n";
    out += "telemetry_anomalies_detected_total{type=\"syn_flood\"} ";
    out += std::to_string(syn);
    out += "\n";
    out += "telemetry_anomalies_detected_total{type=\"port_scan\"} ";
    out += std::to_string(scan);
    out += "\n";
    out += "telemetry_anomalies_detected_total{type=\"suspicious_process\"} ";
    out += std::to_string(proc);
    out += "\n";
    out += "# HELP telemetry_conn_events_total Process correlation events from tracepoints.\n";
    out += "# TYPE telemetry_conn_events_total counter\n";
    out += "telemetry_conn_events_total ";
    out += std::to_string(conns);
    out += "\n";
    out += "# HELP telemetry_active_flows Currently tracked flows.\n";
    out += "# TYPE telemetry_active_flows gauge\n";
    out += "telemetry_active_flows ";
    out += std::to_string(flows);
    out += "\n";
    out += "# HELP telemetry_ring_consumed_total Ring-buffer records dispatched.\n";
    out += "# TYPE telemetry_ring_consumed_total counter\n";
    out += "telemetry_ring_consumed_total ";
    out += std::to_string(consumed);
    out += "\n";
    out += "# HELP telemetry_ring_errors_total Ring-buffer poll errors.\n";
    out += "# TYPE telemetry_ring_errors_total counter\n";
    out += "telemetry_ring_errors_total ";
    out += std::to_string(errors);
    out += "\n";
    return out;
}

namespace {

std::string http_response(int code, std::string_view reason,
                          std::string_view content_type, std::string_view body)
{
    std::string out;
    out.reserve(body.size() + 160);
    out += "HTTP/1.0 ";
    out += std::to_string(code);
    out += " ";
    out += reason;
    out += "\r\nContent-Type: ";
    out += content_type;
    out += "\r\nContent-Length: ";
    out += std::to_string(body.size());
    out += "\r\nConnection: close\r\n\r\n";
    out += body;
    return out;
}

} // namespace

std::string MetricsExporter::handle_request(std::string_view request) const
{
    static constexpr std::string_view kMetricsType =
        "text/plain; version=0.0.4; charset=utf-8";
    static constexpr std::string_view kTextType = "text/plain; charset=utf-8";

    // Minimal request-line parse: METHOD SP TARGET SP VERSION.
    const std::size_t eol = request.find("\r\n");
    const std::string_view line = request.substr(0, eol);
    const std::size_t sp1 = line.find(' ');
    const std::size_t sp2 =
        (sp1 == std::string_view::npos) ? std::string_view::npos
                                        : line.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
        return http_response(400, "Bad Request", kTextType, "bad request\n");
    }
    const std::string_view method = line.substr(0, sp1);
    std::string_view target = line.substr(sp1 + 1, sp2 - sp1 - 1);
    if (method != "GET") {
        return http_response(405, "Method Not Allowed", kTextType,
                             "method not allowed\n");
    }
    const std::size_t q = target.find('?');
    if (q != std::string_view::npos) {
        target = target.substr(0, q);
    }
    if (target == "/metrics") {
        return http_response(200, "OK", kMetricsType, render());
    }
    if (target == "/healthz") {
        return http_response(200, "OK", kTextType, "ok\n");
    }
    return http_response(404, "Not Found", kTextType, "not found\n");
}

#if defined(__linux__) || defined(__APPLE__)

namespace {

void close_fd(int fd) noexcept
{
    if (fd >= 0) {
        (void)::close(fd);
    }
}

bool send_all(int fd, std::string_view data) noexcept
{
    std::size_t sent = 0;
    while (sent < data.size()) {
        const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

} // namespace

bool MetricsExporter::start()
{
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return true; // already running: idempotent
    }
    last_error_.clear();

    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        last_error_ = "socket failed";
        running_.store(false, std::memory_order_release);
        return false;
    }
    const int one = 1;
    // NOLINTNEXTLINE(misc-include-cleaner) — tidy-18 DB gap: SOL_SOCKET and
    // SO_REUSEADDR come from <sys/socket.h> (included above).
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
                       static_cast<socklen_t>(sizeof(one)));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (bind_addr_ == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (::inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr) != 1) {
            last_error_ = "invalid bind address: " + bind_addr_;
            close_fd(fd);
            running_.store(false, std::memory_order_release);
            return false;
        }
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr),
               static_cast<socklen_t>(sizeof(addr))) != 0) {
        last_error_ = "bind failed on " + bind_addr_ + ":" +
                      std::to_string(port_);
        close_fd(fd);
        running_.store(false, std::memory_order_release);
        return false;
    }
    if (::listen(fd, 16) != 0) {
        last_error_ = "listen failed";
        close_fd(fd);
        running_.store(false, std::memory_order_release);
        return false;
    }
    // Learn the ephemeral port when constructed with port 0 (tests).
    sockaddr_in bound{};
    socklen_t blen = static_cast<socklen_t>(sizeof(bound));
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0) {
        port_ = ntohs(bound.sin_port);
    }
    listen_fd_.store(fd, std::memory_order_release);
    try {
        accept_thread_ = std::jthread(
            [this](std::stop_token tok) { accept_loop(tok); });
    } catch (...) {
        last_error_ = "failed to launch accept thread";
        listen_fd_.store(-1, std::memory_order_release);
        close_fd(fd);
        running_.store(false, std::memory_order_release);
        return false;
    }
    return true;
}

void MetricsExporter::stop() noexcept
{
    running_.store(false, std::memory_order_release);
    try {
        if (accept_thread_.joinable()) {
            accept_thread_.request_stop();
        }
    } catch (...) {
        // request_stop() is noexcept in practice; log and continue teardown.
        std::fprintf(stderr, "[telemetry] metrics stop: request_stop threw\n");
    }
    const int fd = listen_fd_.exchange(-1, std::memory_order_acq_rel);
    if (fd >= 0) {
        // Unblock a parked select()/accept() immediately.
        (void)::shutdown(fd, SHUT_RDWR);
        close_fd(fd);
    }
    try {
        if (accept_thread_.joinable()) {
            accept_thread_.join();
        }
    } catch (...) {
        // join() on a joinable thread is not expected to throw; log it.
        std::fprintf(stderr, "[telemetry] metrics stop: join threw\n");
    }
}

void MetricsExporter::accept_loop(std::stop_token tok) noexcept
{
    try {
        while (!tok.stop_requested()) {
            const int fd = listen_fd_.load(std::memory_order_acquire);
            if (fd < 0) {
                break;
            }
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            // NOLINTNEXTLINE(misc-include-cleaner) — see <sys/time.h> note above.
            timeval tv{0, 100000}; // 100 ms stop granularity
            const int rc = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
            if (rc < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (rc == 0 || !FD_ISSET(fd, &rfds)) {
                continue;
            }
            sockaddr_in peer{};
            socklen_t plen = static_cast<socklen_t>(sizeof(peer));
            const int conn = ::accept(
                fd, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (conn < 0) {
                if (errno == EINTR || errno == EAGAIN ||
                    tok.stop_requested()) {
                    continue;
                }
                continue;
            }
            // Inline, bounded handling (metrics cadence is low); the socket
            // carries a 2 s recv timeout so a stalled peer cannot wedge us.
            const timeval rtv{2, 0};
            // NOLINTNEXTLINE(misc-include-cleaner) — SO_RCVTIMEO also comes
            // from <sys/socket.h> (see note above).
            (void)::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &rtv,
                               static_cast<socklen_t>(sizeof(rtv)));
            std::string req;
            req.reserve(1024);
            char buf[2048];
            for (int rounds = 0; rounds < 4; ++rounds) {
                const ssize_t n = ::recv(
                    conn, buf, static_cast<std::size_t>(sizeof(buf)), 0);
                if (n <= 0) {
                    break;
                }
                req.append(buf, static_cast<std::size_t>(n));
                if (req.find("\r\n\r\n") != std::string::npos ||
                    req.size() >= 8192) {
                    break;
                }
            }
            const std::string resp =
                handle_request(std::string_view{req.data(), req.size()});
            (void)send_all(conn, std::string_view{resp.data(), resp.size()});
            close_fd(conn);
        }
    } catch (...) {
        // Only std::bad_alloc can realistically escape the loop above;
        // report it — the accept thread must never die silently.
        std::fprintf(stderr,
                     "[telemetry] metrics accept loop exiting on exception\n");
    }
}

#else /* non-POSIX stub: counters + rendering stay fully functional */

bool MetricsExporter::start()
{
    last_error_ = "TCP accept loop unsupported on this platform (stub mode)";
    running_.store(false, std::memory_order_release);
    return false;
}

void MetricsExporter::stop() noexcept
{
    running_.store(false, std::memory_order_release);
}

void MetricsExporter::accept_loop(std::stop_token /*tok*/) noexcept
{
}

#endif

} // namespace telemetry
