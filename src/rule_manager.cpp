// ============================================================================
// rule_manager.cpp — Blocking rules engine implementation
// NetScope DPI Lite
// ============================================================================

#include "rule_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <shared_mutex>

namespace NetScope {

// ============================================================================
// loadRules — parse rules.conf
//
// Supported directives:
//   block_ip     192.168.1.50
//   block_app    YouTube
//   block_domain tiktok.com
//   block_port   4444
// Lines starting with '#' are comments.
// ============================================================================
int RuleManager::loadRules(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[RuleManager] Cannot open rules file: " << filename << '\n';
        return -1;
    }

    int count = 0;
    std::string line;

    while (std::getline(file, line)) {
        // Strip comments and trim whitespace
        auto hash_pos = line.find('#');
        if (hash_pos != std::string::npos) line = line.substr(0, hash_pos);
        while (!line.empty() && std::isspace(line.back())) line.pop_back();
        while (!line.empty() && std::isspace(line.front()))
            line.erase(line.begin());

        if (line.empty()) continue;

        std::istringstream ss(line);
        std::string directive, value;
        ss >> directive >> value;

        if (directive == "block_ip" && !value.empty()) {
            blockIP(value);
            ++count;
        } else if (directive == "block_app" && !value.empty()) {
            blockApp(value);
            ++count;
        } else if (directive == "block_domain" && !value.empty()) {
            blockDomain(value);
            ++count;
        } else if (directive == "block_port" && !value.empty()) {
            try {
                blockPort(static_cast<uint16_t>(std::stoul(value)));
                ++count;
            } catch (...) {
                std::cerr << "[RuleManager] Invalid port: " << value << '\n';
            }
        } else if (!directive.empty()) {
            std::cerr << "[RuleManager] Unknown directive: " << directive << '\n';
        }
    }

    std::cout << "[RuleManager] Loaded " << count << " rules from " << filename << '\n';
    return count;
}

// ============================================================================
// blockIP
// ============================================================================
void RuleManager::blockIP(uint32_t src_ip) {
    std::unique_lock lock(ip_mutex_);
    blocked_ips_.insert(src_ip);
}

void RuleManager::blockIP(const std::string& ip_str) {
    blockIP(parseIPString(ip_str));
    std::cout << "[RuleManager] Block IP: " << ip_str << '\n';
}

// ============================================================================
// blockApp
// ============================================================================
void RuleManager::blockApp(AppType app) {
    std::unique_lock lock(app_mutex_);
    blocked_apps_.insert(static_cast<int>(app));
}

void RuleManager::blockApp(const std::string& app_name) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
        std::string name = appTypeToString(static_cast<AppType>(i));
        if (name == app_name || 
            (static_cast<AppType>(i) == AppType::TWITTER && app_name == "Twitter")) {
            blockApp(static_cast<AppType>(i));
            std::cout << "[RuleManager] Block App: " << app_name << '\n';
            return;
        }
    }
    std::cerr << "[RuleManager] Unknown app: " << app_name << '\n';
}

// ============================================================================
// blockDomain — supports "*.facebook.com" wildcard prefix
// ============================================================================
void RuleManager::blockDomain(const std::string& pattern) {
    std::unique_lock lock(domain_mutex_);
    blocked_domains_.push_back(pattern);
    std::cout << "[RuleManager] Block domain pattern: " << pattern << '\n';
}

// ============================================================================
// blockPort
// ============================================================================
void RuleManager::blockPort(uint16_t port) {
    std::unique_lock lock(port_mutex_);
    blocked_ports_.insert(port);
    std::cout << "[RuleManager] Block port: " << port << '\n';
}

// ============================================================================
// shouldBlock — hot path; called per packet by workers
// ============================================================================
FlowAction RuleManager::shouldBlock(uint32_t     src_ip,
                                    uint16_t     dst_port,
                                    AppType      app,
                                    const std::string& domain) const {
    // 1. IP blacklist
    {
        std::shared_lock lock(ip_mutex_);
        if (blocked_ips_.count(src_ip)) return FlowAction::DROP;
    }
    // 2. Port blacklist
    {
        std::shared_lock lock(port_mutex_);
        if (blocked_ports_.count(dst_port)) return FlowAction::DROP;
    }
    // 3. App blacklist
    {
        std::shared_lock lock(app_mutex_);
        if (blocked_apps_.count(static_cast<int>(app))) return FlowAction::DROP;
    }
    // 4. Domain pattern
    if (!domain.empty() && isDomainBlocked(domain)) return FlowAction::DROP;

    return FlowAction::FORWARD;
}

// ============================================================================
// isDomainBlocked — substring + simple wildcard matching
// ============================================================================
bool RuleManager::isDomainBlocked(const std::string& domain) const {
    std::shared_lock lock(domain_mutex_);
    for (const auto& pattern : blocked_domains_) {
        if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
            // Wildcard: "*.facebook.com" matches "www.facebook.com"
            const std::string suffix = pattern.substr(1); // ".facebook.com"
            if (domain.size() >= suffix.size() &&
                domain.compare(domain.size() - suffix.size(),
                                suffix.size(), suffix) == 0)
                return true;
        } else {
            // Substring match
            if (domain.find(pattern) != std::string::npos) return true;
        }
    }
    return false;
}

// ============================================================================
// ruleCount / printRules
// ============================================================================
size_t RuleManager::ruleCount() const {
    std::shared_lock l1(ip_mutex_), l2(app_mutex_),
                     l3(domain_mutex_), l4(port_mutex_);
    return blocked_ips_.size() + blocked_apps_.size() +
           blocked_domains_.size() + blocked_ports_.size();
}

void RuleManager::printRules() const {
    std::shared_lock l1(ip_mutex_), l2(app_mutex_),
                     l3(domain_mutex_), l4(port_mutex_);
    std::cout << "[RuleManager] Active rules:\n";
    std::cout << "  IPs:     " << blocked_ips_.size()     << '\n';
    std::cout << "  Apps:    " << blocked_apps_.size()    << '\n';
    std::cout << "  Domains: " << blocked_domains_.size() << '\n';
    std::cout << "  Ports:   " << blocked_ports_.size()   << '\n';
}

// ============================================================================
// parseIPString — "a.b.c.d" → uint32_t host byte order
// ============================================================================
uint32_t RuleManager::parseIPString(const std::string& ip) {
    uint32_t result = 0;
    int octet = 0, shift = 24;
    for (char c : ip) {
        if (c == '.') {
            result |= (static_cast<uint32_t>(octet) << shift);
            shift -= 8;
            octet = 0;
        } else if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= (static_cast<uint32_t>(octet) << shift);
    return result;
}

} // namespace NetScope
