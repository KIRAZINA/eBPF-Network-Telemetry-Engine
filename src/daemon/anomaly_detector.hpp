#pragma once

// anomaly_detector.hpp — real-time telemetry triage (C++20).
//
// Rules (evaluated per record on the analytics thread):
//   1. SYN burst  — per-source SlidingWindowCounter over XDP SYN telemetry;
//                   fires when R_current > syn_flood_threshold.
//   2. Port scan  — distinct-dst-port fan-out per source from the
//                   ConnectionTracker; fires at >= port_scan_threshold.
//   3. Suspicious process — CONN_INIT with an empty comm (kernel-thread
//                   impersonation placeholder) or, when flag_root_execve is
//                   set, a root-owned exec/connect correlation event.
//
// Threading: per-source windows live in mutex shards (one lock per evaluate,
// never nested → deadlock-free); diagnostic counters are atomics. evaluate()
// performs no I/O; alert text/logging is the caller's job via the AlertSink.

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "connection_tracker.hpp"
#include "event_types.h"
#include "sliding_window.hpp"

namespace telemetry {

enum class AnomalyKind : std::uint8_t {
    kSynFlood = 0,
    kPortScan = 1,
    kSuspiciousProcess = 2,
};

struct AnomalyConfig {
    double syn_flood_threshold = 100.0;      // SYN events per 100 ms window
    std::size_t port_scan_threshold = 20;    // distinct dst ports per source
    std::size_t port_scan_cap = 64;          // fan-out scan early-exit bound
    bool flag_root_execve = true;            // triage root-owned CONN_INIT
    bool flag_empty_comm = true;             // triage empty-comm CONN_INIT
};

struct Verdict {
    AnomalyKind kind = AnomalyKind::kSynFlood;
    std::uint32_t src_ip = 0;
    double observed_rate = 0.0;      // meaningful for kSynFlood
    std::size_t distinct_ports = 0;  // meaningful for kPortScan
    telemetry_event anomaly{};       // EVENT_ANOMALY record for the ring/logs
    std::string reason;              // human-readable alert text
};

using AlertSink = std::function<void(const Verdict&)>;

class AnomalyDetector {
public:
    explicit AnomalyDetector(ConnectionTracker& tracker,
                             AnomalyConfig config = AnomalyConfig{});
    ~AnomalyDetector() = default;

    AnomalyDetector(const AnomalyDetector&) = delete;
    AnomalyDetector& operator=(const AnomalyDetector&) = delete;

    // Triage one record. Returns a Verdict on anomaly, std::nullopt when
    // benign. Thread-safe; hot path is hash lookups + atomic ops (≈100–300 ns
    // on the target; heap allocation happens only when building a Verdict).
    [[nodiscard]] std::optional<Verdict> evaluate(
        const telemetry_event& evt);

    void set_sink(AlertSink sink);

    [[nodiscard]] std::uint64_t evaluated() const noexcept
    {
        return evaluated_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t anomalies() const noexcept
    {
        return anomalies_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t syn_alerts() const noexcept
    {
        return syn_alerts_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t scan_alerts() const noexcept
    {
        return scan_alerts_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t process_alerts() const noexcept
    {
        return process_alerts_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] const AnomalyConfig& config() const noexcept
    {
        return config_;
    }

private:
    static constexpr std::size_t kWindowShards = 32;

    struct WindowShard {
        mutable std::mutex mutex;
        std::unordered_map<std::uint32_t,
                           std::unique_ptr<SlidingWindowCounter>>
            windows;
    };

    [[nodiscard]] double observe_syn(std::uint32_t src_ip,
                                     std::uint64_t now_ns);

    ConnectionTracker& tracker_;
    AnomalyConfig config_;
    std::array<WindowShard, kWindowShards> syn_windows_{};
    AlertSink sink_;
    std::mutex sink_mutex_;
    std::atomic<std::uint64_t> evaluated_{0};
    std::atomic<std::uint64_t> anomalies_{0};
    std::atomic<std::uint64_t> syn_alerts_{0};
    std::atomic<std::uint64_t> scan_alerts_{0};
    std::atomic<std::uint64_t> process_alerts_{0};
};

} // namespace telemetry
