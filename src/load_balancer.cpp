// ============================================================================
// load_balancer.cpp — Flow-affine packet dispatcher implementation
// NetScope DPI Lite
// ============================================================================

#include "load_balancer.h"
#include "logger.h"

namespace NetScope {

LoadBalancer::LoadBalancer(
    std::vector<ThreadSafeQueue<PacketJob>*> worker_queues)
    : worker_queues_(std::move(worker_queues)),
      input_queue_(50000) {}

LoadBalancer::~LoadBalancer() { stop(); }

void LoadBalancer::start() {
    running_ = true;
    thread_  = std::thread(&LoadBalancer::run, this);
    LOG_INFO << "[LoadBalancer] Started. Workers: " << worker_queues_.size();
}

void LoadBalancer::stop() {
    running_ = false;
    input_queue_.shutdown();
    if (thread_.joinable()) thread_.join();
}

void LoadBalancer::run() {
    const size_t N = worker_queues_.size();

    while (running_) {
        auto job = input_queue_.popWithTimeout(std::chrono::milliseconds(50));
        if (!job) continue;

        // Flow-affine routing: hash(5-tuple) % N
        // All packets of the same flow → same worker → no locking on flow table
        size_t worker_idx = hasher_(job->tuple) % N;
        worker_queues_[worker_idx]->push(std::move(*job));
        dispatched_.fetch_add(1, std::memory_order_relaxed);
    }

    LOG_INFO << "[LoadBalancer] Stopped. Dispatched: " << dispatched_.load();
}

} // namespace NetScope
