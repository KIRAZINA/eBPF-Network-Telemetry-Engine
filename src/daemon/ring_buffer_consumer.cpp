// ring_buffer_consumer.cpp — polling loop + libbpf lifetime management.

#include "ring_buffer_consumer.hpp"

#include <chrono>
#include <thread>
#include <utility>

#ifdef HAVE_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#endif

namespace telemetry {

void RingBufferDeleter::operator()(::ring_buffer* rb) const noexcept
{
#ifdef HAVE_LIBBPF
    if (rb != nullptr) {
        ::ring_buffer__free(rb);
    }
#else
    (void)rb; // stub: nothing was ever allocated
#endif
}

RingBufferConsumer::RingBufferConsumer(int map_fd, EventCallback cb)
    : callback_(std::move(cb))
{
#ifdef HAVE_LIBBPF
    if (map_fd >= 0 && callback_ != nullptr) {
        ::ring_buffer* raw =
            ::ring_buffer__new(map_fd, &dispatch_event, &callback_, nullptr);
        rb_.reset(raw); // nullptr when libbpf fails: valid() reports false
    }
#else
    (void)map_fd;
#endif
}

RingBufferConsumer::RingBufferConsumer(EventCallback cb)
    : callback_(std::move(cb))
{
    // No kernel handle: inject_for_test() / direct dispatch only.
}

RingBufferConsumer::~RingBufferConsumer() = default;

// std::atomic is neither copyable nor movable, so the moves below transfer
// the callback/handle and snapshot the counters (relaxed: stats only).
RingBufferConsumer::RingBufferConsumer(RingBufferConsumer&& o) noexcept
    : callback_(std::move(o.callback_))
    , rb_(std::move(o.rb_))
{
    consumed_.store(o.consumed_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
    errors_.store(o.errors_.load(std::memory_order_relaxed),
                  std::memory_order_relaxed);
}

RingBufferConsumer& RingBufferConsumer::operator=(RingBufferConsumer&& o) noexcept
{
    if (this != &o) {
        callback_ = std::move(o.callback_);
        rb_ = std::move(o.rb_);
        consumed_.store(o.consumed_.load(std::memory_order_relaxed),
                        std::memory_order_relaxed);
        errors_.store(o.errors_.load(std::memory_order_relaxed),
                      std::memory_order_relaxed);
    }
    return *this;
}

bool RingBufferConsumer::valid() const noexcept
{
    return rb_ != nullptr;
}

int RingBufferConsumer::poll_once(int timeout_ms) noexcept
{
#ifdef HAVE_LIBBPF
    if (rb_ == nullptr) {
        return -1;
    }
    const int rc = ::ring_buffer__poll(rb_.get(), timeout_ms);
    if (rc < 0) {
        errors_.fetch_add(1, std::memory_order_relaxed);
        return rc;
    }
    if (rc > 0) {
        consumed_.fetch_add(static_cast<std::uint64_t>(rc),
                            std::memory_order_relaxed);
    }
    return rc;
#else
    (void)timeout_ms;
    return -1; // stub: no kernel ring available off-Linux
#endif
}

void RingBufferConsumer::run(std::stop_token tok, int timeout_ms) noexcept
{
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }
    while (!tok.stop_requested()) {
        if (rb_ == nullptr) {
            // Degraded/test mode: no kernel handle — idle-sleep so the
            // worker never busy-spins, still exits promptly on stop.
            std::this_thread::sleep_for(
                std::chrono::milliseconds(timeout_ms));
            continue;
        }
        // Bounded wait: poll returns after timeout_ms even with no events,
        // so stop_requested() is re-checked promptly (no deadlock, no
        // signal juggling inside the worker).
        (void)poll_once(timeout_ms);
    }
}

bool RingBufferConsumer::inject_for_test(std::span<const std::byte> raw)
{
    if (callback_ == nullptr) {
        return false;
    }
    const telemetry_event* evt = nullptr;
    if (!parse_event(raw, evt) || evt == nullptr) {
        return false;
    }
    callback_(*evt);
    consumed_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

} // namespace telemetry
