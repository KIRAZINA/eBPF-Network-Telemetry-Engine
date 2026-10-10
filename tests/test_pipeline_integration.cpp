// test_pipeline_integration.cpp — ring bytes -> queue -> engine -> metrics.
//
// Simulates the full user-space path without a kernel: raw telemetry_event
// blobs enter through RingBufferConsumer::inject_for_test (the same zero-copy
// parse/dispatch used by ring_buffer__poll), queue in EventQueue, triaged by
// ConnectionTracker + AnomalyDetector, and counted by MetricsExporter. The
// final render() must reflect every stage — proving end-to-end flow plus
// metric increments in one deterministic scenario.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

#include "anomaly_detector.hpp"
#include "connection_tracker.hpp"
#include "event_queue.hpp"
#include "metrics_exporter.hpp"
#include "ring_buffer_consumer.hpp"

using telemetry::AnomalyConfig;
using telemetry::AnomalyDetector;
using telemetry::ConnectionTracker;
using telemetry::EventQueue;
using telemetry::MetricsExporter;
using telemetry::RingBufferConsumer;

namespace {

telemetry_event make_evt(std::uint32_t saddr, std::uint16_t dport,
                         std::uint32_t type, std::uint64_t ts)
{
    telemetry_event e{};
    e.timestamp_ns = ts;
    e.src_ip = saddr;
    e.dst_ip = 0x0A000002U;
    e.src_port = 4000;
    e.dst_port = dport;
    e.pid = 4242;
    e.uid = 1000;
    e.event_type = type;
    std::strncpy(e.comm, "nginx", sizeof(e.comm) - 1);
    return e;
}

bool contains(const std::string& hay, const char* needle)
{
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("ring bytes flow through queue, engine and metrics", "[pipeline]")
{
    EventQueue queue{4096};
    RingBufferConsumer consumer{[&queue](const telemetry_event& evt) {
        (void)queue.push(evt);
    }};

    // Phase 1: SYN burst — 30 identical-5-tuple XDP events inside ~30 ms.
    const std::uint64_t t0 = 50'000'000'000ULL;
    for (int i = 0; i < 30; ++i) {
        const telemetry_event e =
            make_evt(0x0A000099U, 80, EVENT_PACKET_DROP,
                     t0 + static_cast<std::uint64_t>(i) * 1'000'000ULL);
        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(&e), sizeof(e));
        REQUIRE(consumer.inject_for_test(bytes));
    }
    // Phase 2: port scan — 12 distinct dst ports as CONN_INIT (never trips
    // the SYN rule, which only watches PACKET_DROP/ANOMALY).
    for (std::uint16_t p = 0; p < 12; ++p) {
        const telemetry_event e =
            make_evt(0x0A000099U, p, EVENT_CONN_INIT, t0 + 500'000'000ULL);
        const auto bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(&e), sizeof(e));
        REQUIRE(consumer.inject_for_test(bytes));
    }
    CHECK(consumer.consumed() == 42);
    CHECK(queue.size() == 42);

    // Analytics pass (mirrors the daemon worker): observe -> exporter ->
    // detector, with the sink feeding per-type anomaly counters.
    ConnectionTracker tracker;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 10.0;
    cfg.port_scan_threshold = 8;
    AnomalyDetector detector{tracker, cfg};
    MetricsExporter exporter{0};
    detector.set_sink([&exporter](const telemetry::Verdict& v) {
        exporter.inc_anomaly(v.kind);
    });

    telemetry_event evt{};
    std::size_t drained = 0;
    while (queue.try_pop(evt)) {
        ++drained;
        tracker.observe(evt);
        exporter.observe_event(evt);
        (void)detector.evaluate(evt);
    }
    exporter.set_active_flows(tracker.size());
    exporter.set_ring_stats(consumer.consumed(), consumer.errors());

    CHECK(drained == 42);
    // 30 SYN + 12 scan events share one source but distinct 5-tuples:
    // 1 SYN flow + 12 scan flows = 13 tracked flows.
    CHECK(tracker.size() == 13);

    const std::string body = exporter.render();
    CHECK(contains(body, "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} 30"));
    CHECK(contains(body, "telemetry_conn_events_total 12"));
    // Deterministic verdict counts: the 30-event/30 ms SYN burst crosses
    // rate 10 at the 11th record (20 verdicts); the scan fan-out reaches 8
    // distinct ports (incl. port 80 from phase 1) at the 7th scan record
    // (6 verdicts).
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"syn_flood\"} 20"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"port_scan\"} 6"));
    CHECK(contains(body, "telemetry_active_flows 13"));
    CHECK(contains(body, "telemetry_ring_consumed_total 42"));

    // The same metrics are reachable over the (pure) HTTP layer.
    const std::string resp = exporter.handle_request("GET /metrics HTTP/1.0\r\n\r\n");
    CHECK(contains(resp, "200 OK"));
    CHECK(contains(resp, "telemetry_active_flows 13"));

    CHECK(detector.evaluated() == 42);
    CHECK(detector.syn_alerts() == 20);
    CHECK(detector.scan_alerts() == 6);
    // Short reads never reach the queue (zero-copy guard).
    const std::array<std::byte, 8> tiny{};
    CHECK_FALSE(consumer.inject_for_test(tiny));
    CHECK(consumer.consumed() == 42);
}
