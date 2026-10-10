#pragma once

// sliding_window.hpp — lock-free sliding-window rate estimator (header-only).
//
// Rate model (per key, two buckets, 100 ms granularity):
//   R = Count_current + Count_previous * (1 - (t - t_bucket_start) / D)
// where t_bucket_start is the start of the CURRENT bucket and D the duration.
//
// Concurrency: all state is std::atomic; add() is lock-free (a bounded CAS
// retry loop with a non-blocking fallback) and rate()/exceeds() are wait-free
// loads. Torn reads may perturb an estimate by one rotation but never block
// or corrupt state — acceptable for a rate hint; exact accounting is not
// promised under concurrent rotation.

#include <array>
#include <atomic>
#include <cstdint>

namespace telemetry {

class SlidingWindowCounter {
public:
    static constexpr std::uint64_t kBucketDurationNs = 100'000'000ULL; // 100 ms
    static constexpr int kMaxRotationAttempts = 4;

    SlidingWindowCounter() noexcept
        : counts_{std::uint64_t{0}, std::uint64_t{0}}
        , bucket_start_ns_{std::uint64_t{0}}
        , current_{0U}
    {
    }

    SlidingWindowCounter(const SlidingWindowCounter&) = delete;
    SlidingWindowCounter& operator=(const SlidingWindowCounter&) = delete;

    // Record `n` events observed at timestamp `now_ns`. Lock-free.
    void add(std::uint64_t now_ns, std::uint64_t n = 1ULL) noexcept
    {
        std::uint64_t start =
            bucket_start_ns_.load(std::memory_order_relaxed);
        if (start == std::uint64_t{0}) {
            // First use: claim the epoch. The loser falls through and
            // retries against the winner's epoch below.
            if (bucket_start_ns_.compare_exchange_strong(
                    start, now_ns, std::memory_order_relaxed)) {
                counts_[current_.load(std::memory_order_relaxed)].fetch_add(
                    n, std::memory_order_relaxed);
                return;
            }
        }
        for (int attempt = 0; attempt < kMaxRotationAttempts; ++attempt) {
            const unsigned cur = current_.load(std::memory_order_relaxed);
            start = bucket_start_ns_.load(std::memory_order_relaxed);
            if (start == std::uint64_t{0} || now_ns < start) {
                // Unclaimed or backward clock: count without rotating.
                counts_[cur].fetch_add(n, std::memory_order_relaxed);
                return;
            }
            const std::uint64_t elapsed = now_ns - start;
            if (elapsed < kBucketDurationNs) {
                counts_[cur].fetch_add(n, std::memory_order_relaxed);
                return;
            }
            // Window expired: the CAS winner advances the epoch and resets
            // the next bucket. A gap >= 2 windows also clears the stale
            // bucket so decay never resurrects ancient counts.
            const unsigned nxt = static_cast<unsigned>((cur + 1U) % 2U);
            std::uint64_t expected = start;
            if (bucket_start_ns_.compare_exchange_weak(
                    expected, now_ns, std::memory_order_relaxed)) {
                counts_[nxt].store(n, std::memory_order_relaxed);
                if (elapsed >= 2ULL * kBucketDurationNs) {
                    counts_[cur].store(std::uint64_t{0},
                                       std::memory_order_relaxed);
                }
                current_.store(nxt, std::memory_order_relaxed);
                return;
            }
            // Lost the race: the winner already advanced the epoch; retry
            // so this increment lands in the fresh window exactly once.
        }
        // Extremely contended fallback: count without rotating (never blocks).
        counts_[current_.load(std::memory_order_relaxed)].fetch_add(
            n, std::memory_order_relaxed);
    }

    // Estimate current rate (events per bucket window) at `now_ns`.
    // Wait-free; never advances state.
    [[nodiscard]] double rate(std::uint64_t now_ns) const noexcept
    {
        const unsigned cur = current_.load(std::memory_order_relaxed);
        const unsigned prv = static_cast<unsigned>((cur + 1U) % 2U);
        const std::uint64_t start =
            bucket_start_ns_.load(std::memory_order_relaxed);
        if (start == std::uint64_t{0}) {
            return 0.0;
        }

        const auto cur_c = static_cast<double>(
            counts_[cur].load(std::memory_order_relaxed));
        const auto prv_c = static_cast<double>(
            counts_[prv].load(std::memory_order_relaxed));

        std::uint64_t elapsed =
            (now_ns > start) ? (now_ns - start) : std::uint64_t{0};
        if (elapsed > kBucketDurationNs) {
            elapsed = kBucketDurationNs;
        }
        const double frac = 1.0 - (static_cast<double>(elapsed) /
                                   static_cast<double>(kBucketDurationNs));
        return cur_c + prv_c * frac;
    }

    [[nodiscard]] bool exceeds(std::uint64_t now_ns,
                               double threshold) const noexcept
    {
        return rate(now_ns) > threshold;
    }

private:
    std::array<std::atomic<std::uint64_t>, 2> counts_;
    std::atomic<std::uint64_t> bucket_start_ns_;
    std::atomic<unsigned> current_;
};

} // namespace telemetry
