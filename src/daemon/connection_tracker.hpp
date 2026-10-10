#pragma once

// connection_tracker.hpp — sharded concurrent flow table (C++20).
//
// Tracks active 5-tuple flows: packet counters, byte volumes, SYN counts and
// lifecycle timestamps. Concurrency: N independent shards, each with its own
// mutex + unordered_map. No operation ever holds two shard locks at once, so
// lock ordering is trivially deadlock-free; hot-path observe() touches exactly
// one shard. Stale flows are reclaimed by evict_older_than() or, when a shard
// is full, by oldest-entry eviction on insert (fail-open under flood).

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "event_types.h"

namespace telemetry {

// Network-order 5-tuple identifying one flow.
struct FlowKey {
    std::uint32_t saddr = 0;
    std::uint32_t daddr = 0;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint8_t proto = 0;

    bool operator==(const FlowKey& o) const noexcept
    {
        return saddr == o.saddr && daddr == o.daddr && sport == o.sport &&
               dport == o.dport && proto == o.proto;
    }
};

struct FlowKeyHash {
    [[nodiscard]] std::size_t operator()(const FlowKey& k) const noexcept
    {
        // FNV-1a over the packed tuple (branch-free, no allocations).
        std::size_t h = static_cast<std::size_t>(14695981039346656037ULL);
        const auto mix = [&h](std::uint64_t v) {
            h ^= static_cast<std::size_t>(v);
            h *= static_cast<std::size_t>(1099511628211ULL);
        };
        mix(k.saddr);
        mix(k.daddr);
        mix((static_cast<std::uint64_t>(k.sport) << 16U) | k.dport);
        mix(k.proto);
        return h;
    }
};

struct FlowStats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t syn_count = 0;
    std::uint64_t first_seen_ns = 0;
    std::uint64_t last_seen_ns = 0;
    std::uint32_t last_event = 0;
};

class ConnectionTracker {
public:
    static constexpr std::size_t kShards = 32;
    static constexpr std::size_t kDefaultMaxFlows = 65536;

    explicit ConnectionTracker(
        std::size_t max_flows = kDefaultMaxFlows);
    ~ConnectionTracker() = default;

    ConnectionTracker(const ConnectionTracker&) = delete;
    ConnectionTracker& operator=(const ConnectionTracker&) = delete;

    // Fold one telemetry record into the table (exactly one shard locked).
    // byte_len carries L3/L4 volume when the caller knows it (0 if unknown).
    void observe(const telemetry_event& evt,
                 std::uint64_t byte_len = std::uint64_t{0});

    [[nodiscard]] std::optional<FlowStats> lookup(const FlowKey& key) const;

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] bool empty() const { return size() == 0; }

    // Remove flows idle longer than idle_timeout_ns at time now_ns.
    // Returns the number of evicted flows.
    std::size_t evict_older_than(std::uint64_t now_ns,
                                 std::uint64_t idle_timeout_ns);

    // Distinct destination ports contacted by src (early-exits at cap).
    // Used for port-scan fan-out detection with bounded cost.
    [[nodiscard]] std::size_t count_distinct_ports_from(
        std::uint32_t src_ip, std::size_t cap = 64) const;

    [[nodiscard]] std::size_t count_flows_from(std::uint32_t src_ip) const;

    void clear();

    [[nodiscard]] std::size_t max_flows() const noexcept { return max_flows_; }

    static FlowKey key_of(const telemetry_event& evt) noexcept;

private:
    struct Shard {
        mutable std::mutex mutex;
        std::unordered_map<FlowKey, FlowStats, FlowKeyHash> map;
    };

    [[nodiscard]] Shard& shard_for(const FlowKey& k) noexcept;
    [[nodiscard]] const Shard& shard_for(const FlowKey& k) const noexcept;

    std::array<Shard, kShards> shards_;
    std::size_t max_flows_;
};

} // namespace telemetry
