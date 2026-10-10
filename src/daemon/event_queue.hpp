#pragma once

// event_queue.hpp — bounded thread-safe dispatch queue (MPSC, C++20).
//
// Moves parsed telemetry records from the ring-buffer polling thread to the
// analytics pipeline. Records are 48 bytes; the queue stores them by value
// (one copy out of the zero-copy ring view) under a mutex, woken via
// std::condition_variable_any so waiters can cooperatively cancel with a
// std::stop_token — no manual flag loops, no lost wakeups.

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <stop_token>

#include "event_types.h"

namespace telemetry {

class EventQueue {
public:
    explicit EventQueue(std::size_t capacity = 4096)
        : capacity_(capacity == 0 ? std::size_t{1} : capacity)
    {
    }

    EventQueue(const EventQueue&) = delete;
    EventQueue& operator=(const EventQueue&) = delete;

    // Push one record (copied out of the zero-copy ring view). Drops the
    // oldest entry when full (fail-open under flood) and returns false
    // only when the queue has been shut down.
    bool push(const telemetry_event& evt)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (closed_) {
            return false;
        }
        if (queue_.size() >= capacity_) {
            queue_.pop_front(); // shed load: keep newest telemetry
            ++dropped_;
        }
        queue_.push_back(evt);
        ++pushed_;
        lock.unlock();
        cv_.notify_one();
        return true;
    }

    bool try_pop(telemetry_event& out)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return false;
        }
        out = queue_.front();
        queue_.pop_front();
        return true;
    }

    // Blocking pop, cooperatively cancellable via stop_token or shutdown().
    // Returns false on stop/shutdown with an empty queue.
    bool wait_pop(telemetry_event& out, std::stop_token tok)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const bool got = cv_.wait(lock, tok,
                                  [this] { return !queue_.empty() || closed_; });
        if (!got || queue_.empty()) {
            return false;
        }
        out = queue_.front();
        queue_.pop_front();
        return true;
    }

    void shutdown() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = false;
        queue_.clear();
    }

    [[nodiscard]] std::size_t size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    [[nodiscard]] bool empty() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    [[nodiscard]] bool closed() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return closed_;
    }

    [[nodiscard]] std::size_t dropped() const noexcept { return dropped_; }
    [[nodiscard]] std::size_t pushed() const noexcept { return pushed_; }

private:
    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    std::deque<telemetry_event> queue_;
    std::size_t capacity_;
    bool closed_ = false;
    std::size_t dropped_ = 0;
    std::size_t pushed_ = 0;
};

} // namespace telemetry
