#pragma once
// ============================================================================
// rule_manager.h — Blocking rules engine
// NetScope DPI Lite
//
// Supports 4 rule types:
//   1. IP blacklist       (block_ip)
//   2. App blacklist      (block_app)
//   3. Domain patterns    (block_domain — substring match + wildcard *.domain)
//   4. Port blacklist     (block_port)
//
// Thread safety:
//   - shared_mutex per rule set (many readers / single writer)
//   - Workers call shouldBlock() concurrently (read lock only)
//   - Hot-reload via reloadRules() (write lock, brief pause)
// ============================================================================

#include "types.h"
#include <unordered_set>
#include <vector>
#include <string>
#include <shared_mutex>
#include <mutex>

namespace NetScope {

class RuleManager {
public:
    RuleManager() = default;

    // ---------- Loading ----------

    // Load rules from rules.conf file format.
    // Replaces ALL existing rules.
    // Returns number of rules successfully loaded.
    int loadRules(const std::string& filename);

    // ---------- Individual rule setters ----------
    void blockIP(uint32_t src_ip);
    void blockIP(const std::string& ip_str);
    void blockApp(AppType app);
    void blockApp(const std::string& app_name);
    void blockDomain(const std::string& pattern);  // supports *.domain.com
    void blockPort(uint16_t port);

    // ---------- Decision ----------

    // Called by FastPathWorker on every packet.
    // Returns DROP if any rule matches, FORWARD otherwise.
    FlowAction shouldBlock(uint32_t     src_ip,
                           uint16_t     dst_port,
                           AppType      app,
                           const std::string& domain) const;

    // ---------- Query ----------
    size_t ruleCount() const;
    void   printRules() const;

private:
    mutable std::shared_mutex ip_mutex_;
    mutable std::shared_mutex app_mutex_;
    mutable std::shared_mutex domain_mutex_;
    mutable std::shared_mutex port_mutex_;

    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<int>      blocked_apps_;    // stores AppType as int
    std::vector<std::string>     blocked_domains_; // substring / wildcard patterns
    std::unordered_set<uint16_t> blocked_ports_;

    // Helper: check if domain matches any blocked pattern
    bool isDomainBlocked(const std::string& domain) const;

    // Helper: parse "192.168.1.50" → uint32_t (host byte order)
    static uint32_t parseIPString(const std::string& ip);
};

} // namespace NetScope
