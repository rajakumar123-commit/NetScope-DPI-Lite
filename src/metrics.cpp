#include "metrics.h"
#include "logger.h"
#include "platform.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// POSIX socket headers (Linux / WSL2 / Docker)
#ifdef _WIN32
  #include <winsock2.h>
  #pragma comment(lib, "ws2_32.lib")
  typedef int socklen_t;
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #define closesocket close
#endif

namespace NetScope {

MetricsServer::MetricsServer(uint16_t port) : port_(port) {
    for (auto& a : app_counts_)   a.store(0);
    for (auto& a : queue_sizes_)  a.store(0);
}

MetricsServer::~MetricsServer() { stop(); }

// ============================================================================
// start / stop
// ============================================================================
void MetricsServer::start() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    listen_fd_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (listen_fd_ < 0) {
        LOG_ERROR << "[Metrics] socket() failed";
        return;
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = hostToNet16(port_);  // use platform.h portable version

    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR << "[Metrics] bind() failed on port " << port_;
        closesocket(listen_fd_);
        listen_fd_ = -1;
        return;
    }

    listen(listen_fd_, 8);
    running_ = true;
    server_thread_ = std::thread(&MetricsServer::serverLoop, this);
    LOG_INFO << "[Metrics] Prometheus endpoint: http://0.0.0.0:" << port_ << "/metrics";
}

void MetricsServer::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        closesocket(listen_fd_);
        listen_fd_ = -1;
    }
    if (server_thread_.joinable()) server_thread_.join();
}

// ============================================================================
// serverLoop — accept + serve /metrics
// ============================================================================
void MetricsServer::serverLoop() {
    while (running_) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = static_cast<int>(
            accept(listen_fd_,
                   reinterpret_cast<sockaddr*>(&client_addr), &client_len));
        if (client_fd < 0) break;
        handleClient(client_fd);
        closesocket(client_fd);
    }
}

void MetricsServer::handleClient(int client_fd) {
    // Read HTTP request (we ignore it — always serve /metrics)
    char buf[1024];
    recv(client_fd, buf, sizeof(buf) - 1, 0);

    std::string body   = renderMetrics();
    std::string header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n";

    std::string response = header + body;
    send(client_fd, response.c_str(), static_cast<int>(response.size()), 0);
}

// ============================================================================
// Hot-path recording (lock-free atomic ops)
// ============================================================================
void MetricsServer::recordPacket(uint64_t bytes) {
    packets_total_.fetch_add(1, std::memory_order_relaxed);
    bytes_total_.fetch_add(bytes, std::memory_order_relaxed);
}

void MetricsServer::recordForwarded() {
    forwarded_total_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::recordDropped() {
    dropped_total_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::recordTCP() {
    tcp_total_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::recordUDP() {
    udp_total_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::recordApp(AppType app) {
    int idx = static_cast<int>(app);
    if (idx >= 0 && idx < static_cast<int>(AppType::APP_COUNT))
        app_counts_[idx].fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::recordLatencyMs(double ms) {
    lat_sum_us_.fetch_add(static_cast<uint64_t>(ms * 1000),
                          std::memory_order_relaxed);
    lat_count_.fetch_add(1, std::memory_order_relaxed);
    lat_bucket_inf_.fetch_add(1, std::memory_order_relaxed);
    if (ms <= 10.0) lat_bucket_10_.fetch_add(1, std::memory_order_relaxed);
    if (ms <=  5.0) lat_bucket_5_.fetch_add(1,  std::memory_order_relaxed);
    if (ms <=  1.0) lat_bucket_1_.fetch_add(1,  std::memory_order_relaxed);
    if (ms <=  0.1) lat_bucket_01_.fetch_add(1, std::memory_order_relaxed);
}

void MetricsServer::setActiveFlows(size_t count) {
    active_flows_.store(count, std::memory_order_relaxed);
}

void MetricsServer::setQueueSize(int worker_id, size_t size) {
    if (worker_id >= 0 && worker_id < MAX_WORKERS)
        queue_sizes_[worker_id].store(size, std::memory_order_relaxed);
}

// ============================================================================
// renderMetrics — Prometheus text format
// ============================================================================
std::string MetricsServer::renderMetrics() const {
    std::ostringstream ss;

    auto counter = [&](const char* name, const char* help,
                       uint64_t value) {
        ss << "# HELP " << name << ' ' << help << '\n'
           << "# TYPE " << name << " counter\n"
           << name << ' ' << value << '\n';
    };
    auto gauge = [&](const char* name, const char* help, uint64_t value) {
        ss << "# HELP " << name << ' ' << help << '\n'
           << "# TYPE " << name << " gauge\n"
           << name << ' ' << value << '\n';
    };

    // Counters
    counter("netscope_packets_processed_total",
            "Total packets processed", packets_total_.load());
    counter("netscope_bytes_processed_total",
            "Total bytes processed", bytes_total_.load());
    counter("netscope_packets_forwarded_total",
            "Total packets forwarded", forwarded_total_.load());
    counter("netscope_packets_dropped_total",
            "Total packets dropped", dropped_total_.load());
    counter("netscope_tcp_packets_total",
            "Total TCP packets", tcp_total_.load());
    counter("netscope_udp_packets_total",
            "Total UDP packets", udp_total_.load());

    // Gauge
    gauge("netscope_active_flows",
          "Current tracked flows", active_flows_.load());

    // Per-app counters
    ss << "# HELP netscope_app_packets_total Packets per application\n"
       << "# TYPE netscope_app_packets_total counter\n";
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
        uint64_t v = app_counts_[i].load();
        if (v > 0) {
            ss << "netscope_app_packets_total{app=\""
               << appTypeToString(static_cast<AppType>(i)) << "\"} " << v << '\n';
        }
    }

    // Per-worker queue sizes
    ss << "# HELP netscope_worker_queue_size Current worker queue depth\n"
       << "# TYPE netscope_worker_queue_size gauge\n";
    for (int i = 0; i < MAX_WORKERS; ++i) {
        uint64_t v = queue_sizes_[i].load();
        if (v > 0)
            ss << "netscope_worker_queue_size{worker=\"" << i << "\"} " << v << '\n';
    }

    // Histogram
    uint64_t cnt = lat_count_.load();
    double sum_ms = static_cast<double>(lat_sum_us_.load()) / 1000.0;
    ss << "# HELP netscope_processing_latency_ms Processing latency\n"
       << "# TYPE netscope_processing_latency_ms histogram\n"
       << "netscope_processing_latency_ms_bucket{le=\"0.1\"} "
       << lat_bucket_01_.load() << '\n'
       << "netscope_processing_latency_ms_bucket{le=\"1\"} "
       << lat_bucket_1_.load()  << '\n'
       << "netscope_processing_latency_ms_bucket{le=\"5\"} "
       << lat_bucket_5_.load()  << '\n'
       << "netscope_processing_latency_ms_bucket{le=\"10\"} "
       << lat_bucket_10_.load() << '\n'
       << "netscope_processing_latency_ms_bucket{le=\"+Inf\"} "
       << lat_bucket_inf_.load()<< '\n'
       << "netscope_processing_latency_ms_sum " << std::fixed
       << std::setprecision(3) << sum_ms << '\n'
       << "netscope_processing_latency_ms_count " << cnt << '\n';

    return ss.str();
}

} // namespace NetScope
