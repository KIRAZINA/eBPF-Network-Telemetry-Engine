// test_event_layout.cpp — ABI stability for the shared kernel/user-space header.

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>

#include "event_types.h"

TEST_CASE("telemetry_event ABI is binary-compatible", "[abi]")
{
    STATIC_REQUIRE(sizeof(telemetry_event) == 48);
    STATIC_REQUIRE(alignof(telemetry_event) == 8);
    STATIC_REQUIRE(offsetof(telemetry_event, timestamp_ns) == 0);
    STATIC_REQUIRE(offsetof(telemetry_event, src_ip) == 8);
    STATIC_REQUIRE(offsetof(telemetry_event, dst_ip) == 12);
    STATIC_REQUIRE(offsetof(telemetry_event, src_port) == 16);
    STATIC_REQUIRE(offsetof(telemetry_event, dst_port) == 18);
    STATIC_REQUIRE(offsetof(telemetry_event, pid) == 20);
    STATIC_REQUIRE(offsetof(telemetry_event, uid) == 24);
    STATIC_REQUIRE(offsetof(telemetry_event, event_type) == 28);
    STATIC_REQUIRE(offsetof(telemetry_event, comm) == 32);
    STATIC_REQUIRE(sizeof(telemetry_event::comm) == TELEMETRY_TASK_COMM_LEN);

    CHECK(static_cast<std::uint32_t>(TELEMETRY_EVENT_PACKET_DROP) == 1);
    CHECK(static_cast<std::uint32_t>(TELEMETRY_EVENT_CONN_INIT) == 2);
    CHECK(static_cast<std::uint32_t>(TELEMETRY_EVENT_ANOMALY) == 3);
}
