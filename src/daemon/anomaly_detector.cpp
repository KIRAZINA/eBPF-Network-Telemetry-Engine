// anomaly_detector.cpp — triage implementation (I/O-free hot path).

#include "anomaly_detector.hpp"

#include <cstdio>
#include <utility>

namespace telemetry {

AnomalyDetector::AnomalyDetector(ConnectionTracker& tracker,
                                 AnomalyConfig config)
    : tracker_(tracker)
    , config_(config)
{
}

void AnomalyDetector::set_sink(AlertSink sink)
{
    std::lock_guard<std::mutex> lock(sink_mutex_);
    sink_ = std::move(sink);
}

double AnomalyDetector::observe_syn(std::uint32_t src_ip,
                                    std::uint64_t now_ns)
{
    WindowShard& shard =
        syn_windows_[src_ip % kWindowShards]; // NOLINT: power-of-two mod
    std::lock_guard<std::mutex> lock(shard.mutex);
    auto it = shard.windows.find(src_ip);
    if (it == shard.windows.end()) {
        auto counter = std::make_unique<SlidingWindowCounter>();
        counter->add(now_ns, std::uint64_t{1});
        const double r = counter->rate(now_ns);
        shard.windows.emplace(src_ip, std::move(counter));
        return r;
    }
    it->second->add(now_ns, std::uint64_t{1});
    return it->second->rate(now_ns);
}

std::optional<Verdict> AnomalyDetector::evaluate(const telemetry_event& evt)
{
    evaluated_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
    const std::uint64_t now = evt.timestamp_ns;

    // --- Rule 1: SYN burst over XDP SYN telemetry -------------------------
    if (evt.event_type == EVENT_PACKET_DROP || evt.event_type == EVENT_ANOMALY) {
        const double rate = observe_syn(evt.src_ip, now);
        if (rate > config_.syn_flood_threshold) {
            Verdict v;
            v.kind = AnomalyKind::kSynFlood;
            v.src_ip = evt.src_ip;
            v.observed_rate = rate;
            v.anomaly = evt;
            v.anomaly.event_type = EVENT_ANOMALY;
            v.reason = "SYN burst: src rate " + std::to_string(rate) +
                       " exceeds " + std::to_string(config_.syn_flood_threshold) +
                       " per 100ms window";
            anomalies_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
            syn_alerts_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
            AlertSink sink;
            {
                std::lock_guard<std::mutex> lock(sink_mutex_);
                sink = sink_;
            }
            if (sink != nullptr) {
                sink(v);
            }
            return v;
        }
    }

    // --- Rule 2: port-scan fan-out ----------------------------------------
    if (evt.event_type == EVENT_PACKET_DROP || evt.event_type == EVENT_ANOMALY ||
        evt.event_type == EVENT_CONN_INIT) {
        const std::size_t ports = tracker_.count_distinct_ports_from(
            evt.src_ip, config_.port_scan_cap);
        if (ports >= config_.port_scan_threshold && ports > 0) {
            Verdict v;
            v.kind = AnomalyKind::kPortScan;
            v.src_ip = evt.src_ip;
            v.distinct_ports = ports;
            v.anomaly = evt;
            v.anomaly.event_type = EVENT_ANOMALY;
            v.reason = "Port scan: " + std::to_string(ports) +
                       " distinct dst ports from one source";
            anomalies_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
            scan_alerts_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
            AlertSink sink;
            {
                std::lock_guard<std::mutex> lock(sink_mutex_);
                sink = sink_;
            }
            if (sink != nullptr) {
                sink(v);
            }
            return v;
        }
    }

    // --- Rule 3: suspicious process correlation ---------------------------
    if (evt.event_type == EVENT_CONN_INIT) {
        const bool empty_comm = (evt.comm[0] == '\0');
        const bool root_event = (evt.uid == 0);
        if ((config_.flag_empty_comm && empty_comm) ||
            (config_.flag_root_execve && root_event && empty_comm)) {
            Verdict v;
            v.kind = AnomalyKind::kSuspiciousProcess;
            v.src_ip = evt.src_ip;
            v.anomaly = evt;
            v.anomaly.event_type = EVENT_ANOMALY;
            v.reason = std::string{"Suspicious process network event: pid="} +
                       std::to_string(evt.pid) +
                       " uid=" + std::to_string(evt.uid);
            anomalies_.fetch_add(std::uint64_t{1}, std::memory_order_relaxed);
            process_alerts_.fetch_add(std::uint64_t{1},
                                      std::memory_order_relaxed);
            AlertSink sink;
            {
                std::lock_guard<std::mutex> lock(sink_mutex_);
                sink = sink_;
            }
            if (sink != nullptr) {
                sink(v);
            }
            return v;
        }
    }

    return std::nullopt;
}

} // namespace telemetry
