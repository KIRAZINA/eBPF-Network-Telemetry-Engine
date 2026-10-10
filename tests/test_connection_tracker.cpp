// test_connection_tracker.cpp — flow table correctness + concurrency stress.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

#include "connection_tracker.hpp"

using telemetry::ConnectionTracker;
using telemetry::FlowKey;

namespace {

telemetry_event make_evt(std::uint32_t saddr, std::uint32_t daddr,
                         std::uint16_t sport, std::uint16_t dport,
                         std::uint32_t type, std::uint64_t ts)
{
    telemetry_event e{};
    e.timestamp_ns = ts;
    e.src_ip = saddr;
    e.dst_ip = daddr;
    e.src_port = sport;
    e.dst_port = dport;
    e.pid = 1234;
    e.uid = 1000;
    e.event_type = type;
    std::strncpy(e.comm, "test-proc", sizeof(e.comm) - 1);
    return e;
}

} // namespace

TEST_CASE("observe then lookup round-trips counters", "[tracker]")
{
    ConnectionTracker t;
    const auto e = make_evt(0x0A000001U, 0x0A000002U, 1234, 80,
                            EVENT_PACKET_DROP, 1'000'000'000ULL);
    t.observe(e);
    t.observe(e, 500);

    FlowKey k = ConnectionTracker::key_of(e);
    const auto got = t.lookup(k);
    REQUIRE(got.has_value());
    CHECK(got->packets == 2);
    CHECK(got->bytes == 500);
    CHECK(got->syn_count == 2);
    CHECK(got->first_seen_ns == 1'000'000'000ULL);
    CHECK(t.size() == 1);
}

TEST_CASE("distinct flows are tracked independently", "[tracker]")
{
    ConnectionTracker t;
    for (std::uint16_t p = 0; p < 10; ++p) {
        t.observe(make_evt(0x0A000001U, 0x0A000002U, 1000, p,
                           EVENT_PACKET_DROP, 1'000'000'000ULL));
    }
    CHECK(t.size() == 10);
    CHECK(t.count_flows_from(0x0A000001U) == 10);
    CHECK(t.count_distinct_ports_from(0x0A000001U) == 10);
    CHECK(t.count_distinct_ports_from(0x0A000001U, 5) == 5); // early-exit cap
    CHECK(t.count_flows_from(0xDEADBEEFU) == 0);
}

TEST_CASE("stale flows are evicted, fresh flows survive", "[tracker]")
{
    ConnectionTracker t;
    t.observe(make_evt(1, 2, 11, 80, EVENT_CONN_INIT, 1'000'000'000ULL));
    t.observe(make_evt(3, 4, 12, 443, EVENT_CONN_INIT, 90'000'000'000ULL));

    const std::size_t evicted =
        t.evict_older_than(100'000'000'000ULL, 60'000'000'000ULL);
    CHECK(evicted == 1);
    CHECK(t.size() == 1);
    // Survivor is the recent flow.
    CHECK(t.count_flows_from(3) == 1);
    CHECK(t.count_flows_from(1) == 0);
}

TEST_CASE("shard capacity bounds memory under unique-flood", "[tracker]")
{
    ConnectionTracker t{256}; // tiny table: 8 flows per shard
    for (std::uint32_t i = 0; i < 5000; ++i) {
        t.observe(make_evt(i + 1, 0x0A000002U, 1000, 80, EVENT_CONN_INIT,
                           1'000'000'000ULL + i));
    }
    CHECK(t.size() <= 256);
}

TEST_CASE("concurrent observe from 8 threads loses nothing and never deadlocks",
          "[tracker][stress]")
{
    ConnectionTracker t;
    constexpr int kThreads = 8;
    constexpr int kPerThread = 2000;
    std::atomic<int> ready{0};
    std::vector<std::thread> th;
    for (int w = 0; w < kThreads; ++w) {
        th.emplace_back([&, w] {
            ready.fetch_add(1);
            while (ready.load() < kThreads) {
                std::this_thread::yield();
            }
            for (int i = 0; i < kPerThread; ++i) {
                // Disjoint 5-tuples per thread (no shared-key contention),
                // plus one shared hot key hammered by everyone.
                t.observe(make_evt(static_cast<std::uint32_t>(w + 1), 9, 5000,
                                   static_cast<std::uint16_t>(i),
                                   EVENT_PACKET_DROP,
                                   1'000'000'000ULL + static_cast<std::uint64_t>(i)));
                t.observe(make_evt(0xC0A80001U, 0xC0A80002U, 80, 8080,
                                   EVENT_CONN_INIT, 2'000'000'000ULL));
            }
        });
    }
    for (auto& x : th) {
        x.join();
    }
    CHECK(t.size() == static_cast<std::size_t>(kThreads * kPerThread + 1));
    // Hot key saw every hammer blow exactly once (atomicity under contention).
    const auto hot = t.lookup(telemetry::FlowKey{
        0xC0A80001U, 0xC0A80002U, 80, 8080, 6});
    REQUIRE(hot.has_value());
    CHECK(hot->packets == static_cast<std::uint64_t>(kThreads * kPerThread));
}
