#pragma once

// metrics_exporter.hpp — embedded Prometheus exposition endpoint (C++20).
//
// Serves GET /metrics in Prometheus text format on port 9090 (default) via a
// small POSIX-socket HTTP/1.0 server driven by std::jthread + std::stop_token.
// No third-party HTTP dependency: request parsing and routing are pure
// functions (handle_request) unit-tested portably; only the accept loop is
// POSIX-gated (Linux/macOS). On other platforms start() reports false and the
// counters/render path still works for tests.
//
// Threading: all counters are relaxed atomics; render() is wait-free. The
// accept loop uses select() with a 100 ms timeout so stop_requested() is
// honored promptly; shutdown() also shutdown()s the listen fd to unblock a
// parked select/accept immediately. start()/stop() are idempotent.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>

#include "event_types.h"

namespace telemetry {

enum class AnomalyKind : std::uint8_t;

class MetricsExporter {
public:
    static constexpr std::uint16_t kDefaultPort = 9090;

    explicit MetricsExporter(std::uint16_t port = kDefaultPort,
                             std::string bind_addr = "0.0.0.0");
    ~MetricsExporter();

    MetricsExporter(const MetricsExporter&) = delete;
    MetricsExporter& operator=(const MetricsExporter&) = delete;
    MetricsExporter(MetricsExporter&&) = delete;
    MetricsExporter& operator=(MetricsExporter&&) = delete;

    // Starts the accept loop. Returns false when sockets are unavailable
    // (non-POSIX platform) or the bind fails; check last_error().
    bool start();
    void stop() noexcept;

    [[nodiscard]] bool running() const noexcept
    {
        return running_.load(std::memory_order_acquire);
    }
    // Actual bound port (useful when constructed with port 0 in tests).
    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] const std::string& last_error() const noexcept
    {
        return last_error_;
    }

    // ---- Ingest-side accounting (called from the analytics thread) ----
    void inc_packets_passed(std::uint64_t n = std::uint64_t{1}) noexcept;
    void inc_packets_dropped_syn(std::uint64_t n = std::uint64_t{1}) noexcept;
    void inc_conn_events(std::uint64_t n = std::uint64_t{1}) noexcept;
    void inc_anomaly(AnomalyKind kind) noexcept;
    void set_active_flows(std::uint64_t n) noexcept;
    void set_ring_stats(std::uint64_t consumed, std::uint64_t errors) noexcept;

    // Classify one raw record into ingest counters (XDP/ring path).
    void observe_event(const telemetry_event& evt) noexcept;

    // ---- Rendering (pure, thread-safe, portable) ----
    [[nodiscard]] std::string render() const;
    // Full HTTP response for a raw request line body (pure; unit-tested).
    [[nodiscard]] std::string handle_request(std::string_view request) const;

private:
    void accept_loop(std::stop_token tok) noexcept;

    std::uint16_t port_;
    std::string bind_addr_;
    std::string last_error_;
    std::atomic<bool> running_{false};
    std::atomic<int> listen_fd_{-1};
    std::jthread accept_thread_;

    std::atomic<std::uint64_t> packets_passed_{0};
    std::atomic<std::uint64_t> packets_dropped_syn_{0};
    std::atomic<std::uint64_t> conn_events_{0};
    std::atomic<std::uint64_t> anomalies_syn_{0};
    std::atomic<std::uint64_t> anomalies_scan_{0};
    std::atomic<std::uint64_t> anomalies_proc_{0};
    std::atomic<std::uint64_t> active_flows_{0};
    std::atomic<std::uint64_t> ring_consumed_{0};
    std::atomic<std::uint64_t> ring_errors_{0};
};

} // namespace telemetry
