#pragma once
// ============================================================================
// thread_safe_queue.h — Bounded blocking producer-consumer queue
// NetScope DPI Lite
//
// Design notes:
//  - Bounded: push() blocks when full → backpressure on reader/LB
//  - shutdown() unblocks ALL waiters via notify_all() (no deadlock on exit)
//  - size() is O(1) via atomic counter (avoids locking just for metrics)
// ============================================================================

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <atomic>
#include <chrono>
#include <cstddef>

namespace NetScope {

template<typename T>
class ThreadSafeQueue {
public:
    explicit ThreadSafeQueue(size_t max_size = 10000)
        : max_size_(max_size), size_(0), shutdown_(false) {}

    // Disable copy — queues are not copyable
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    // ---------- Producer API ----------

    // Blocking push — waits if full. Returns false if shut down.
    bool push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] {
            return queue_.size() < max_size_ || shutdown_;
        });
        if (shutdown_) return false;
        queue_.push(std::move(item));
        ++size_;
        not_empty_.notify_one();
        return true;
    }

    // Non-blocking push — returns false if full or shut down
    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ || shutdown_) return false;
        queue_.push(std::move(item));
        ++size_;
        not_empty_.notify_one();
        return true;
    }

    // ---------- Consumer API ----------

    // Blocking pop — waits until item available or shut down
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] {
            return !queue_.empty() || shutdown_;
        });
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        --size_;
        not_full_.notify_one();
        return item;
    }

    // Timed pop — returns nullopt on timeout or shutdown
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, timeout, [this] {
                return !queue_.empty() || shutdown_;
            })) {
            return std::nullopt; // timed out
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        --size_;
        not_full_.notify_one();
        return item;
    }

    // ---------- Control ----------

    // Signal shutdown — unblocks all waiting push/pop calls
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    // ---------- Query ----------

    size_t size() const { return size_.load(std::memory_order_relaxed); }
    bool   empty() const { return size_.load(std::memory_order_relaxed) == 0; }
    bool   isShutdown() const { return shutdown_.load(); }

private:
    std::queue<T>           queue_;
    mutable std::mutex      mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t                  max_size_;
    std::atomic<size_t>     size_;
    std::atomic<bool>       shutdown_;
};

} // namespace NetScope
