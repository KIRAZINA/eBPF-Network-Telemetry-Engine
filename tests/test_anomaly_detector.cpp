// test_anomaly_detector.cpp — triage rules, stress and perf budget.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "anomaly_detector.hpp"
#include "connection_tracker.hpp"

using telemetry::AnomalyConfig;
using telemetry::AnomalyDetector;
using telemetry::AnomalyKind;
using telemetry::ConnectionTracker;

namespace {

telemetry_event make_evt(std::uint32_t saddr, std::uint32_t daddr,
                         std::uint16_t sport, std::uint16_t dport,
                         std::uint32_t type, std::uint64_t ts,
                         std::uint32_t pid = 4242, std::uint32_t uid = 1000,
                         const char* comm = "nginx")
{
    telemetry_event e{};
    e.timestamp_ns = ts;
    e.src_ip = saddr;
    e.dst_ip = daddr;
    e.src_port = sport;
    e.dst_port = dport;
    e.pid = pid;
    e.uid = uid;
    e.event_type = type;
    if (comm != nullptr) {
        std::strncpy(e.comm, comm, sizeof(e.comm) - 1);
    }
    return e;
}

} // namespace

TEST_CASE("benign traffic produces no verdict", "[anomaly]")
{
    ConnectionTracker t;
    AnomalyDetector d{t};
    const auto e = make_evt(0x0A000001U, 0x0A000002U, 5000, 80,
                            EVENT_CONN_INIT, 1'000'000'000ULL);
    t.observe(e);
    CHECK_FALSE(d.evaluate(e).has_value());
    CHECK(d.evaluated() == 1);
    CHECK(d.anomalies() == 0);
}

TEST_CASE("SYN burst past threshold fires kSynFlood with EVENT_ANOMALY",
          "[anomaly]")
{
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 10.0;
    cfg.port_scan_threshold = 10'000; // isolate the SYN rule
    AnomalyDetector d{t, cfg};

    std::optional<telemetry::Verdict> verdict;
    const std::uint64_t t0 = 5'000'000'000ULL;
    for (int i = 0; i < 30; ++i) {
        const auto e = make_evt(0x0A000099U, 0x0A000002U, 4000, 80,
                                EVENT_PACKET_DROP, t0 + 1'000'000ULL);
        t.observe(e);
        verdict = d.evaluate(e);
        if (verdict.has_value()) {
            break;
        }
    }
    REQUIRE(verdict.has_value());
    CHECK(verdict->kind == AnomalyKind::kSynFlood);
    CHECK(verdict->anomaly.event_type == EVENT_ANOMALY);
    CHECK(verdict->observed_rate > 10.0);
    CHECK(d.syn_alerts() == 1);
    CHECK(d.anomalies() == 1);
}

TEST_CASE("distinct-port fan-out fires kPortScan", "[anomaly]")
{
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 1e9; // isolate the scan rule
    cfg.port_scan_threshold = 8;
    AnomalyDetector d{t, cfg};

    std::optional<telemetry::Verdict> verdict;
    for (std::uint16_t p = 0; p < 12; ++p) {
        const auto e = make_evt(0x0A000007U, 0x0A000009U, 5000, p,
                                EVENT_CONN_INIT, 9'000'000'000ULL);
        t.observe(e);
        verdict = d.evaluate(e);
        if (verdict.has_value()) {
            break;
        }
    }
    REQUIRE(verdict.has_value());
    CHECK(verdict->kind == AnomalyKind::kPortScan);
    CHECK(verdict->distinct_ports >= 8);
    CHECK(d.scan_alerts() == 1);
}

TEST_CASE("empty-comm CONN_INIT fires kSuspiciousProcess", "[anomaly]")
{
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 1e9;
    cfg.port_scan_threshold = 10'000;
    AnomalyDetector d{t, cfg};

    telemetry_event e{};
    e.timestamp_ns = 3'000'000'000ULL;
    e.event_type = EVENT_CONN_INIT;
    e.pid = 999;
    e.uid = 0;
    // comm left zeroed on purpose.
    t.observe(e);
    const auto verdict = d.evaluate(e);
    REQUIRE(verdict.has_value());
    CHECK(verdict->kind == AnomalyKind::kSuspiciousProcess);
    CHECK(d.process_alerts() == 1);
}

TEST_CASE("alert sink receives every anomaly", "[anomaly]")
{
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 5.0;
    cfg.port_scan_threshold = 10'000;
    AnomalyDetector d{t, cfg};
    std::atomic<int> got{0};
    d.set_sink([&got](const telemetry::Verdict&) { got.fetch_add(1); });

    const std::uint64_t t0 = 7'000'000'000ULL;
    for (int i = 0; i < 20; ++i) {
        const auto e = make_evt(0x0B000001U, 2, 4000, 80, EVENT_PACKET_DROP,
                                t0 + 500'000ULL);
        t.observe(e);
        (void)d.evaluate(e);
    }
    CHECK(got.load() >= 1);
    CHECK(static_cast<int>(d.anomalies()) == got.load());
}

TEST_CASE("concurrent evaluate is race-clean (TSan + counters agree)",
          "[anomaly][stress]")
{
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 1e12; // never fires: pure race exercise
    cfg.port_scan_threshold = 10'000;
    AnomalyDetector d{t, cfg};

    constexpr int kThreads = 8;
    constexpr int kPerThread = 2500;
    std::vector<std::thread> th;
    for (int w = 0; w < kThreads; ++w) {
        th.emplace_back([&, w] {
            for (int i = 0; i < kPerThread; ++i) {
                const auto e = make_evt(static_cast<std::uint32_t>(w + 1), 2,
                                        5000,
                                        static_cast<std::uint16_t>(i % 512),
                                        EVENT_CONN_INIT,
                                        11'000'000'000ULL +
                                            static_cast<std::uint64_t>(i));
                t.observe(e);
                (void)d.evaluate(e);
            }
        });
    }
    for (auto& x : th) {
        x.join();
    }
    CHECK(d.evaluated() ==
          static_cast<std::uint64_t>(kThreads * kPerThread));
    CHECK(d.anomalies() == 0);
}

TEST_CASE("evaluate averages well under budget (<20us @ CI clocks)",
          "[anomaly][perf]")
{
    // Production target is <1us/record (hash + atomics ≈ 100–300 ns at -O3);
    // CI asserts a 20x-looser bound to absorb shared-runner noise while still
    // catching algorithmic regressions (locks, copies, scans in hot path).
    ConnectionTracker t;
    AnomalyConfig cfg;
    cfg.syn_flood_threshold = 1e12;
    cfg.port_scan_threshold = 10'000;
    AnomalyDetector d{t, cfg};

    constexpr int kEvents = 20000;
    std::vector<telemetry_event> evts;
    evts.reserve(kEvents);
    for (int i = 0; i < kEvents; ++i) {
        evts.push_back(make_evt(0x0A000001U, 0x0A000002U, 5000,
                                static_cast<std::uint16_t>(80 + (i % 4)),
                                EVENT_CONN_INIT,
                                20'000'000'000ULL +
                                    static_cast<std::uint64_t>(i) * 50'000ULL));
    }
    const auto start = std::chrono::steady_clock::now();
    for (const auto& e : evts) {
        t.observe(e);
        (void)d.evaluate(e);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    const double avg_us =
        std::chrono::duration<double, std::micro>(elapsed).count() / kEvents;
    INFO("avg per-record observe+evaluate: " << avg_us << " us");
    CHECK(avg_us < 20.0);
    CHECK(d.evaluated() == static_cast<std::uint64_t>(kEvents));
}
