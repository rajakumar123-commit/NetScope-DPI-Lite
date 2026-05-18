// ============================================================================
// connection_tracker.cpp — Per-worker flow table implementation
// NetScope DPI Lite
// ============================================================================

#include "connection_tracker.h"
#include <iostream>

namespace NetScope {

ConnectionTracker::ConnectionTracker(int worker_id)
    : worker_id_(worker_id) {}

Connection& ConnectionTracker::getOrCreate(const FiveTuple& tuple) {
    auto it = table_.find(tuple);
    if (it != table_.end()) return it->second;

    // Try reverse direction (server → client)
    FiveTuple rev = tuple.normalised();
    it = table_.find(rev);
    if (it != table_.end()) return it->second;

    // New connection
    Connection& conn  = table_[tuple];
    conn.tuple        = tuple;
    conn.state        = ConnectionState::NEW;
    conn.first_seen   = std::chrono::steady_clock::now();
    conn.last_seen    = conn.first_seen;
    return conn;
}

Connection* ConnectionTracker::find(const FiveTuple& tuple) {
    auto it = table_.find(tuple);
    if (it != table_.end()) return &it->second;

    FiveTuple rev = tuple.normalised();
    it = table_.find(rev);
    if (it != table_.end()) return &it->second;

    return nullptr;
}

size_t ConnectionTracker::cleanupStale(std::chrono::seconds timeout) {
    auto now     = std::chrono::steady_clock::now();
    size_t count = 0;

    for (auto it = table_.begin(); it != table_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
                       now - it->second.last_seen);
        if (age >= timeout) {
            it = table_.erase(it);
            ++count;
        } else {
            ++it;
        }
    }
    return count;
}

} // namespace NetScope
