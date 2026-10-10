#pragma once

// ring_buffer_consumer.hpp — zero-copy ring-buffer dispatch (C++20).
//
// Fast path: libbpf invokes dispatch_event(ctx, data, len) straight from
// ring_buffer__poll(); we build a std::span<const std::byte> over the raw
// ring view and reinterpret it as a telemetry_event WITHOUT copying — the
// only copy in the system happens when the callback pushes the 48 B record
// into the EventQueue for the analytics thread.
//
// The header stays libbpf-free so unit tests exercise parse/dispatch
// portably; the polling loop (which needs struct ring_buffer) lives in
// ring_buffer_consumer.cpp behind a forward declaration + custom deleter.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stop_token>

#include "event_types.h"

// libbpf forward declaration at GLOBAL scope — it must name ::ring_buffer,
// the same type <bpf/libbpf.h> declares. (Declaring it inside namespace
// telemetry would create a distinct, incomplete telemetry::ring_buffer that
// no libbpf API accepts.) Completed by the .cpp's <bpf/libbpf.h> include.
struct ring_buffer;

namespace telemetry {

using EventCallback = std::function<void(const telemetry_event&)>;

// Build a zero-copy view over raw ring memory. Returns false on short reads.
inline bool parse_event(std::span<const std::byte> raw,
                        const telemetry_event*& out) noexcept
{
    if (raw.size() < sizeof(telemetry_event)) {
        out = nullptr;
        return false;
    }
    out = reinterpret_cast<const telemetry_event*>(raw.data());
    return true;
}

// libbpf ring-buffer callback shape: int(void*, void*, size_t). Never throws:
// user-callback exceptions are swallowed to -1 so they never unwind through C.
inline int dispatch_event(void* ctx, void* data, std::size_t len) noexcept
{
    auto* cb = static_cast<EventCallback*>(ctx);
    if ((cb == nullptr) || (*cb == nullptr) || (data == nullptr)) {
        return 0;
    }
    if (len < sizeof(telemetry_event)) {
        return 0;
    }
    const auto bytes = std::span<const std::byte>(
        static_cast<const std::byte*>(data), len);
    const telemetry_event* evt = nullptr;
    if (!parse_event(bytes, evt) || evt == nullptr) {
        return 0;
    }
    try {
        (*cb)(*evt); // 48 B const-ref view; callback copies only if queuing
    } catch (...) {
        return -1;
    }
    return 0;
}

struct RingBufferDeleter {
    void operator()(::ring_buffer* rb) const noexcept;
};
using RingBufferPtr = std::unique_ptr<::ring_buffer, RingBufferDeleter>;

class RingBufferConsumer {
public:
    // Attach to a kernel ringbuf map fd (HAVE_LIBBPF). Invalid fd yields
    // valid()==false; poll_once() then returns -1 instead of crashing.
    explicit RingBufferConsumer(int map_fd, EventCallback cb);
    // Portable seam for tests / off-Linux runs: dispatch path only.
    explicit RingBufferConsumer(EventCallback cb);
    ~RingBufferConsumer();

    RingBufferConsumer(const RingBufferConsumer&) = delete;
    RingBufferConsumer& operator=(const RingBufferConsumer&) = delete;
    RingBufferConsumer(RingBufferConsumer&&) noexcept;
    RingBufferConsumer& operator=(RingBufferConsumer&&) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    // Single non-blocking poll; returns polled count, 0 on timeout, -1 if
    // invalid or on callback error. Never throws.
    int poll_once(int timeout_ms) noexcept;
    // Cooperative loop: returns promptly after stop is requested (bounded by
    // timeout_ms). Never throws; safe to run inside std::jthread.
    void run(std::stop_token tok, int timeout_ms = 100) noexcept;
    // Test seam: drive the zero-copy path without a kernel map.
    bool inject_for_test(std::span<const std::byte> raw);

    [[nodiscard]] std::uint64_t consumed() const noexcept
    {
        return consumed_.load(std::memory_order_relaxed);
    }
    [[nodiscard]] std::uint64_t errors() const noexcept
    {
        return errors_.load(std::memory_order_relaxed);
    }

private:
    EventCallback callback_;
    RingBufferPtr rb_;
    std::atomic<std::uint64_t> consumed_{0};
    std::atomic<std::uint64_t> errors_{0};
};

} // namespace telemetry
