// connection_tracker.cpp — sharded flow table implementation.

#include "connection_tracker.hpp"

#include <limits>
#include <set>

namespace telemetry {

ConnectionTracker::ConnectionTracker(std::size_t max_flows)
    : max_flows_(max_flows == 0 ? kDefaultMaxFlows : max_flows)
{
    for (auto& s : shards_) {
        s.map.reserve(64);
    }
}

FlowKey ConnectionTracker::key_of(const telemetry_event& evt) noexcept
{
    FlowKey k;
    k.saddr = evt.src_ip;
    k.daddr = evt.dst_ip;
    k.sport = evt.src_port;
    k.dport = evt.dst_port;
    // Recover L4 protocol for XDP telemetry: the kernel probe tags floods
    // via event_type; keep proto 0 unless ports indicate TCP/UDP traffic.
    // This normalization lives here (not in observe) so lookup(key_of(e))
    // always names the same bucket observe() filed the event under.
    // event_type occupies the proto slot only for XDP network events; process
    // correlation events (CONN_INIT) share the flow key space harmlessly.
    if (evt.src_port != 0 || evt.dst_port != 0) {
        k.proto = 6; // TCP-dominant probe traffic; refined when BPF exports proto
    }
    return k;
}

ConnectionTracker::Shard& ConnectionTracker::shard_for(
    const FlowKey& k) noexcept
{
    const std::size_t h = FlowKeyHash{}(k);
    return shards_[h % kShards];
}

const ConnectionTracker::Shard& ConnectionTracker::shard_for(
    const FlowKey& k) const noexcept
{
    const std::size_t h = FlowKeyHash{}(k);
    return shards_[h % kShards];
}

void ConnectionTracker::observe(const telemetry_event& evt,
                                std::uint64_t byte_len)
{
    FlowKey k = key_of(evt); // single source of key normalization
    Shard& s = shard_for(k);
    std::lock_guard<std::mutex> lock(s.mutex);

    auto it = s.map.find(k);
    if (it != s.map.end()) {
        FlowStats& st = it->second;
        st.packets += std::uint64_t{1};
        st.bytes += byte_len;
        st.last_seen_ns = evt.timestamp_ns;
        st.last_event = evt.event_type;
        if (evt.event_type == EVENT_ANOMALY ||
            evt.event_type == EVENT_PACKET_DROP) {
            st.syn_count += std::uint64_t{1};
        }
        return;
    }

    // Insert path: enforce per-shard capacity with oldest-entry eviction so a
    // flood of unique 5-tuples cannot grow memory without bound.
    const std::size_t per_shard =
        (max_flows_ / kShards) > 0 ? (max_flows_ / kShards) : std::size_t{1};
    if (s.map.size() >= per_shard) {
        auto oldest = s.map.begin();
        for (auto jt = s.map.begin(); jt != s.map.end(); ++jt) {
            if (jt->second.last_seen_ns < oldest->second.last_seen_ns) {
                oldest = jt;
            }
        }
        s.map.erase(oldest);
    }

    FlowStats st;
    st.packets = std::uint64_t{1};
    st.bytes = byte_len;
    st.syn_count = (evt.event_type == EVENT_ANOMALY ||
                    evt.event_type == EVENT_PACKET_DROP)
                       ? std::uint64_t{1}
                       : std::uint64_t{0};
    st.first_seen_ns = evt.timestamp_ns;
    st.last_seen_ns = evt.timestamp_ns;
    st.last_event = evt.event_type;
    s.map.emplace(k, st);
}

std::optional<FlowStats> ConnectionTracker::lookup(const FlowKey& key) const
{
    const Shard& s = shard_for(key);
    std::lock_guard<std::mutex> lock(s.mutex);
    const auto it = s.map.find(key);
    if (it == s.map.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::size_t ConnectionTracker::size() const
{
    std::size_t total = 0;
    for (const auto& s : shards_) {
        std::lock_guard<std::mutex> lock(s.mutex);
        total += s.map.size();
    }
    return total;
}

std::size_t ConnectionTracker::evict_older_than(
    std::uint64_t now_ns, std::uint64_t idle_timeout_ns)
{
    std::size_t evicted = 0;
    for (auto& s : shards_) {
        std::lock_guard<std::mutex> lock(s.mutex);
        for (auto it = s.map.begin(); it != s.map.end();) {
            const std::uint64_t last = it->second.last_seen_ns;
            const bool stale =
                (now_ns >= last) && ((now_ns - last) > idle_timeout_ns);
            if (stale) {
                it = s.map.erase(it);
                ++evicted;
            } else {
                ++it;
            }
        }
    }
    return evicted;
}

std::size_t ConnectionTracker::count_distinct_ports_from(
    std::uint32_t src_ip, std::size_t cap) const
{
    std::set<std::uint16_t> ports; // small fan-out set; early-exits at cap
    for (const auto& s : shards_) {
        std::lock_guard<std::mutex> lock(s.mutex);
        for (const auto& [k, st] : s.map) {
            (void)st;
            if (k.saddr == src_ip) {
                ports.insert(k.dport);
                if (ports.size() >= cap) {
                    return ports.size();
                }
            }
        }
    }
    return ports.size();
}

std::size_t ConnectionTracker::count_flows_from(std::uint32_t src_ip) const
{
    std::size_t n = 0;
    for (const auto& s : shards_) {
        std::lock_guard<std::mutex> lock(s.mutex);
        for (const auto& [k, st] : s.map) {
            (void)st;
            if (k.saddr == src_ip) {
                ++n;
            }
        }
    }
    return n;
}

void ConnectionTracker::clear()
{
    for (auto& s : shards_) {
        std::lock_guard<std::mutex> lock(s.mutex);
        s.map.clear();
    }
}

} // namespace telemetry
