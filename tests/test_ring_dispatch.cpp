// test_ring_dispatch.cpp — zero-copy parse/dispatch without libbpf.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstring>
#include <string>

#include "ring_buffer_consumer.hpp"

TEST_CASE("parse_event rejects short reads", "[ring]")
{
    const telemetry_event* out = nullptr;
    const std::array<std::byte, 8> tiny{};
    CHECK_FALSE(telemetry::parse_event(tiny, out));
    CHECK(out == nullptr);
}

TEST_CASE("dispatch_event forwards valid records zero-copy", "[ring]")
{
    telemetry_event evt{};
    evt.timestamp_ns = 12345;
    evt.src_ip = 0x01020304U;
    evt.event_type = TELEMETRY_EVENT_CONN_INIT;
    std::strncpy(evt.comm, "test-proc", sizeof(evt.comm) - 1);

    bool called = false;
    telemetry::EventCallback cb = [&](const telemetry_event& got) {
        called = true;
        CHECK(got.timestamp_ns == 12345);
        CHECK(got.event_type == TELEMETRY_EVENT_CONN_INIT);
        CHECK(std::string(got.comm) == "test-proc");
    };

    CHECK(telemetry::dispatch_event(&cb, &evt, sizeof(evt)) == 0);
    CHECK(called);
}

TEST_CASE("dispatch_event drops nulls and short records safely", "[ring]")
{
    telemetry_event evt{};
    CHECK(telemetry::dispatch_event(nullptr, &evt, sizeof(evt)) == 0);

    telemetry::EventCallback empty;
    CHECK(telemetry::dispatch_event(&empty, &evt, sizeof(evt)) == 0);
    CHECK(telemetry::dispatch_event(&empty, nullptr, sizeof(evt)) == 0);

    telemetry::EventCallback cb = [](const telemetry_event&) {};
    CHECK(telemetry::dispatch_event(&cb, &evt, 4) == 0); // short len
}
