// main.cpp — ebpf-telemetry-daemon: BPF load/attach + poll/analysis pipeline.
//
// Threads (all std::jthread, cooperative std::stop_token):
//   poll worker      runs RingBufferConsumer::run() — zero-copy libbpf poll,
//                    callback pushes 48 B records into the EventQueue.
//   analytics worker blocks in EventQueue::wait_pop(tok) — wakes on data,
//                    shutdown(), or stop — and feeds the sliding-window engine.
// Shutdown: SIGINT/SIGTERM sets an async-safe atomic; the main thread then
// request_stop()s both workers and shuts the queue (wakes the waiter). No
// manual join loops, no deadlocks: every blocking wait is bounded by either
// the poll timeout or the stop-aware condition variable.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <stop_token>
#include <string>
#include <thread>

#include "bpf_manager.hpp"
#include "anomaly_detector.hpp"
#include "connection_tracker.hpp"
#include "event_queue.hpp"
#include "event_types.h"
#include "metrics_exporter.hpp"
#include "ring_buffer_consumer.hpp"

namespace {
std::atomic_bool g_stop{false};

void on_signal(int /*signum*/) noexcept
{
    g_stop.store(true, std::memory_order_relaxed);
}
} // namespace

int main(int argc, char** argv)
{
    std::signal(SIGINT, &on_signal);
    std::signal(SIGTERM, &on_signal);

    std::string object_path = "src/kernel/telemetry.bpf.o";
    int ifindex = 0;
    std::uint16_t metrics_port = telemetry::MetricsExporter::kDefaultPort;
    if (argc > 1 && argv[1] != nullptr) {
        object_path = argv[1];
    }
    if (argc > 2 && argv[2] != nullptr) {
        try {
            const long v = std::stol(argv[2]);
            if (v > 0 && v < 65536) {
                ifindex = static_cast<int>(v);
            }
        } catch (...) {
            ifindex = 0;
        }
    }
    if (argc > 3 && argv[3] != nullptr) {
        try {
            const long v = std::stol(argv[3]);
            if (v >= 0 && v < 65536) {
                metrics_port = static_cast<std::uint16_t>(v);
            }
        } catch (...) {
            // Keep the default port; a malformed argv[3] is not fatal.
            metrics_port = telemetry::MetricsExporter::kDefaultPort;
        }
    }

    std::printf("[telemetry] starting (object: %s, ifindex: %d)\n",
                object_path.c_str(), ifindex);

    telemetry::BpfManager mgr{object_path, ifindex};
    int events_fd = -1;
    if (!mgr.open() || !mgr.load()) {
        std::printf("[telemetry] BPF load failed (%s); running degraded.\n",
                    mgr.last_error().c_str());
    } else if (!mgr.attach()) {
        std::printf("[telemetry] BPF attach incomplete (%s); continuing.\n",
                    mgr.last_error().c_str());
        events_fd = mgr.event_map_fd();
    } else {
        std::printf("[telemetry] attached %zu link(s).\n", mgr.link_count());
        events_fd = mgr.event_map_fd();
    }

    telemetry::EventQueue queue{4096};

    // Prometheus exposition (async HTTP on :9090 by default; port 0 disables).
    telemetry::MetricsExporter exporter{metrics_port};
    if (metrics_port != 0) {
        if (exporter.start()) {
            std::printf("[telemetry] metrics at http://0.0.0.0:%u/metrics\n",
                        static_cast<unsigned>(exporter.port()));
        } else {
            std::printf("[telemetry] metrics exporter unavailable (%s).\n",
                        exporter.last_error().c_str());
        }
    }

    // Zero-copy handoff: the poll thread views ring memory, copies 48 B.
    telemetry::RingBufferConsumer consumer{
        events_fd, [&queue](const telemetry_event& evt) {
            (void)queue.push(evt);
        }};
    if (!consumer.valid()) {
        std::printf("[telemetry] ring consumer has no kernel handle "
                    "(expected off-Linux); pipeline idles until stop.\n");
    }

    std::jthread poll_worker([&consumer](std::stop_token tok) {
        consumer.run(tok, 100);
    });

    std::jthread analytics_worker([&queue, &exporter](std::stop_token tok) {
        telemetry::ConnectionTracker tracker;
        telemetry::AnomalyDetector detector{tracker};
        detector.set_sink([&exporter](const telemetry::Verdict& v) {
            std::printf("[telemetry][ALERT] %s\n", v.reason.c_str());
            exporter.inc_anomaly(v.kind);
        });
        std::size_t total = 0;
        std::uint64_t last_evict_ns = 0;
        telemetry_event evt{};
        while (!tok.stop_requested()) {
            if (!queue.wait_pop(evt, tok)) {
                break; // stop requested or shutdown with empty queue
            }
            ++total;
            const std::uint64_t now =
                evt.timestamp_ns != 0
                    ? evt.timestamp_ns
                    : static_cast<std::uint64_t>(
                          std::chrono::steady_clock::now()
                              .time_since_epoch()
                              .count());
            tracker.observe(evt);
            exporter.observe_event(evt);
            (void)detector.evaluate(evt);
            // Reclaim idle flows at ~1 Hz (keyed off event timestamps).
            if (now - last_evict_ns > 1'000'000'000ULL) {
                last_evict_ns = now;
                tracker.evict_older_than(now, 60'000'000'000ULL);
                exporter.set_active_flows(tracker.size());
            }
            if (total % 1000U == 0U) {
                std::printf("[telemetry] processed %zu events "
                            "(flows=%zu anomalies=%llu queue=%zu dropped=%zu)\n",
                            total, tracker.size(),
                            static_cast<unsigned long long>(
                                detector.anomalies()),
                            queue.size(), queue.dropped());
            }
        }
        std::printf("[telemetry] analytics exiting after %zu events, %llu anomalies.\n",
                    total,
                    static_cast<unsigned long long>(detector.anomalies()));
    });

    while (!g_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Graceful teardown: stop poll first (stops producing), wake the waiter,
    // then stop analytics. jthread joins automatically at scope exit.
    poll_worker.request_stop();
    queue.shutdown();
    analytics_worker.request_stop();
    exporter.set_ring_stats(consumer.consumed(), consumer.errors());
    exporter.stop();

    std::printf("[telemetry] poll consumed=%llu errors=%llu; shutdown.\n",
                static_cast<unsigned long long>(consumer.consumed()),
                static_cast<unsigned long long>(consumer.errors()));
    return 0;
}
