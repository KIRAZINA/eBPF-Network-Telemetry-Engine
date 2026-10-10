// test_sliding_window.cpp — sliding-window rate estimator behaviour.

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>

#include "sliding_window.hpp"

using telemetry::SlidingWindowCounter;

TEST_CASE("empty window reports zero rate", "[sliding_window]")
{
    SlidingWindowCounter w;
    CHECK(w.rate(0) == Catch::Approx(0.0));
    CHECK_FALSE(w.exceeds(0, 1.0));
}

TEST_CASE("single bucket accumulates linearly", "[sliding_window]")
{
    SlidingWindowCounter w;
    const std::uint64_t t0 = 1'000'000'000ULL;
    w.add(t0, 5);
    CHECK(w.rate(t0) == Catch::Approx(5.0));

    w.add(t0 + 10'000'000ULL, 3); // +10 ms, same bucket
    CHECK(w.rate(t0 + 10'000'000ULL) == Catch::Approx(8.0));
}

TEST_CASE("bucket rollover decays previous counts", "[sliding_window]")
{
    SlidingWindowCounter w;
    const std::uint64_t t0 = 1'000'000'000ULL;
    const std::uint64_t step = SlidingWindowCounter::kBucketDurationNs;

    w.add(t0, 10);
    // Jump past one full bucket: previous=10 weighted by (1 - elapsed/window).
    const std::uint64_t t1 = t0 + step + step / 2U; // forces rollover at t0+step first
    w.add(t0 + step + 1ULL, 4);
    const double r = w.rate(t1);
    // current=4, previous=10 * (1 - (t1-(t0+step))/step) = 10*0.5 = 5 -> ~9
    CHECK(r == Catch::Approx(9.0).margin(0.001));
    CHECK(w.exceeds(t1, 8.0));
    CHECK_FALSE(w.exceeds(t1, 10.0));
}
