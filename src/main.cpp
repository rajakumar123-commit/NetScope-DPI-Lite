// ============================================================================
// main.cpp — NetScope DPI Lite engine orchestrator
// NetScope DPI Lite
//
// Pipeline:
//   [Reader Thread] → raw_queue
//   [LoadBalancer Thread] → worker_queues[N]
//   [Worker 0..N-1] → output_queue
//   [Writer Thread] → output.pcap
//   [Metrics Thread] → :9100/metrics
// ============================================================================

#include "platform.h"
#include "types.h"
#include "pcap_reader.h"
#include "packet_parser.h"
#include "thread_safe_queue.h"
#include "connection_tracker.h"
#include "rule_manager.h"
#include "load_balancer.h"
#include "fast_path.h"
#include "metrics.h"
#include "logger.h"

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>

using namespace NetScope;

// ============================================================================
// CLI usage
// ============================================================================
static void printUsage(const char* prog) {
    std::cout << R"(
+==============================================================+
|             NetScope DPI Lite - v1.0                         |
|  Multithreaded Deep Packet Inspection Engine (C++17)         |
+==============================================================+

Usage: )" << prog << R"( --pcap <input.pcap> [options]

Options:
  --pcap     <file>    Input PCAP file (required)
  --out      <file>    Output PCAP file [default: output/output.pcap]
  --rules    <file>    Blocking rules file [default: rules.conf]
  --workers  <N>       Number of worker threads [default: 4]
  --log      <file>    Log file path [default: logs/engine.log]
  --metrics  <port>    Prometheus metrics port [default: 9100]
  --no-metrics         Disable Prometheus endpoint
  --help               Show this help

Examples:
  )" << prog << R"( --pcap pcaps/test_dpi.pcap --workers 4
  )" << prog << R"( --pcap capture.pcap --rules rules.conf --out filtered.pcap
)";
}

// ============================================================================
// Parse FiveTuple from ParsedPacket
// ============================================================================
static FiveTuple makeTuple(const ParsedPacket& p) {
    return { p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol };
}

// ============================================================================
// Print final report to stdout
// ============================================================================
static void printReport(const DPIStats& stats,
                        const std::vector<std::unique_ptr<FastPathWorker>>& workers,
                        double elapsed_sec) {
    auto sep  = "+==============================================================+\n";
    auto line = "|                                                              |\n";
    (void)line;

    std::cout << '\n';
    std::cout << "+==============================================================+\n";
    std::cout << "|              NETSCOPE DPI LITE - PROCESSING REPORT           |\n";
    std::cout << sep;
    std::cout << "|  Total Packets:   " << std::setw(12) << stats.total_packets.load()
              << "                            |\n";
    std::cout << "|  Total Bytes:     " << std::setw(12) << stats.total_bytes.load()
              << "                            |\n";
    std::cout << "|  Forwarded:       " << std::setw(12) << stats.forwarded_packets.load()
              << "                            |\n";
    std::cout << "|  Dropped:         " << std::setw(12) << stats.dropped_packets.load()
              << "                            |\n";
    std::cout << "|  TCP Packets:     " << std::setw(12) << stats.tcp_packets.load()
              << "                            |\n";
    std::cout << "|  UDP Packets:     " << std::setw(12) << stats.udp_packets.load()
              << "                            |\n";
    std::cout << "|  Elapsed (s):     " << std::setw(12) << std::fixed
              << std::setprecision(2) << elapsed_sec
              << "                            |\n";

    std::cout << sep;
    std::cout << "|  WORKER STATISTICS                                           |\n";
    std::cout << sep;
    for (const auto& w : workers) {
        std::cout << "|  Worker " << w->id()
                  << ": processed=" << std::setw(8) << w->processed()
                  << " fwd=" << std::setw(7) << w->forwarded()
                  << " drop=" << std::setw(6) << w->dropped()
                  << " flows=" << std::setw(5) << w->flowCount()
                  << "  |\n";
    }

    std::cout << sep;
    std::cout << "|  APPLICATION BREAKDOWN                                       |\n";
    std::cout << sep;

    // Sort by count
    std::vector<std::pair<AppType, uint64_t>> app_list;
    uint64_t total = stats.total_packets.load();
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); ++i) {
        uint64_t cnt = stats.app_packets[i].load();
        if (cnt > 0)
            app_list.push_back({static_cast<AppType>(i), cnt});
    }
    std::sort(app_list.begin(), app_list.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    for (const auto& [app, cnt] : app_list) {
        double pct = total > 0 ? 100.0 * cnt / total : 0.0;
        int    bar = static_cast<int>(pct / 4);
        std::string bar_str(bar, '#');
        std::cout << "|  " << std::setw(14) << std::left << appTypeToString(app)
                  << std::setw(8) << std::right << cnt
                  << " " << std::setw(5) << std::fixed << std::setprecision(1)
                  << pct << "% "
                  << std::setw(18) << std::left << bar_str << "  |\n";
    }

    std::cout << "+==============================================================+\n";
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char* argv[]) {
    // ---- Parse CLI -----------------------------------------------------------
    std::string pcap_file;
    std::string out_file     = "output/output.pcap";
    std::string rules_file   = "rules.conf";
    std::string log_file     = "logs/engine.log";
    int         num_workers  = 4;
    uint16_t    metrics_port = 9100;
    bool        use_metrics  = true;
    bool        daemon_mode  = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if      (arg == "--pcap"    && i+1<argc) pcap_file    = argv[++i];
        else if (arg == "--out"     && i+1<argc) out_file     = argv[++i];
        else if (arg == "--rules"   && i+1<argc) rules_file   = argv[++i];
        else if (arg == "--workers" && i+1<argc) num_workers  = std::stoi(argv[++i]);
        else if (arg == "--log"     && i+1<argc) log_file     = argv[++i];
        else if (arg == "--metrics" && i+1<argc) metrics_port = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (arg == "--no-metrics")          use_metrics  = false;
        else if (arg == "--daemon")              daemon_mode  = true;
        else if (arg == "--help") { printUsage(argv[0]); return 0; }
    }

    if (pcap_file.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    // Ensure output directories exist
    std::filesystem::create_directories("output");
    std::filesystem::create_directories("logs");
    std::filesystem::create_directories("reports");

    // ---- Logger init ---------------------------------------------------------
    Logger::instance().init(log_file, LogLevel::INFO);
    LOG_INFO << "NetScope DPI Lite starting...";
    LOG_INFO << "PCAP:    " << pcap_file;
    LOG_INFO << "Output:  " << out_file;
    LOG_INFO << "Workers: " << num_workers;

    // ---- Open PCAP -----------------------------------------------------------
    PcapReader reader;
    if (!reader.open(pcap_file)) return 1;

    // ---- Load rules ----------------------------------------------------------
    RuleManager rules;
    rules.loadRules(rules_file);
    rules.printRules();

    // ---- Statistics ----------------------------------------------------------
    DPIStats stats;

    // ---- Metrics server ------------------------------------------------------
    MetricsServer metrics(metrics_port);
    if (use_metrics) metrics.start();

    // ---- Output queue + writer -----------------------------------------------
    ThreadSafeQueue<PacketJob> output_queue(20000);

    PcapWriter writer;
    if (!writer.open(out_file, reader.getGlobalHeader())) return 1;

    std::atomic<bool> writer_running{true};
    std::thread writer_thread([&]() {
        while (writer_running || !output_queue.empty()) {
            auto pkt = output_queue.popWithTimeout(std::chrono::milliseconds(50));
            if (!pkt) continue;
            writer.writePacket(pkt->ts_sec, pkt->ts_usec,
                               pkt->data.data(),
                               static_cast<uint32_t>(pkt->data.size()));
        }
    });

    // ---- Create workers + load balancer --------------------------------------
    std::vector<std::unique_ptr<FastPathWorker>> workers;
    std::vector<ThreadSafeQueue<PacketJob>*>     worker_queues;

    for (int i = 0; i < num_workers; ++i) {
        workers.push_back(std::make_unique<FastPathWorker>(
            i, &rules, &metrics, &stats, &output_queue));
        worker_queues.push_back(&workers.back()->inputQueue());
    }

    LoadBalancer lb(worker_queues);

    // ---- Start pipeline -------------------------------------------------------
    for (auto& w : workers) w->start();
    lb.start();

    // ---- Reader loop (main thread) -------------------------------------------
    std::cout << "\n[Reader] Processing packets...\n";
    auto t0 = std::chrono::steady_clock::now();

    RawPacket    raw;
    ParsedPacket parsed;
    uint32_t     pkt_id = 0;

    while (reader.readNextPacket(raw)) {
        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;

        PacketJob job;
        job.packet_id      = pkt_id++;
        job.ts_sec         = raw.header.ts_sec;
        job.ts_usec        = raw.header.ts_usec;
        job.tuple          = makeTuple(parsed);
        job.data           = std::move(raw.data);
        job.tcp_flags      = parsed.tcp_flags;
        job.payload_offset = parsed.payload_offset;
        job.payload_length = parsed.payload_length;

        if (parsed.has_tcp) stats.tcp_packets.fetch_add(1, std::memory_order_relaxed);
        else                stats.udp_packets.fetch_add(1, std::memory_order_relaxed);

        lb.inputQueue().push(std::move(job));
    }

    LOG_INFO << "[Reader] Done. " << pkt_id << " packets dispatched.";
    reader.close();

    // ---- Drain + shutdown ----------------------------------------------------
    // Give workers time to drain queues
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    lb.stop();
    for (auto& w : workers) w->stop();

    writer_running = false;
    output_queue.shutdown();
    writer_thread.join();
    writer.close();

    auto t1      = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();

    // ---- Final report --------------------------------------------------------
    printReport(stats, workers, elapsed);
    std::cout << "\nOutput PCAP: " << out_file << '\n';
    std::cout << "Log file:    " << log_file  << '\n';
    if (use_metrics)
        std::cout << "Metrics:     http://localhost:" << metrics_port << "/metrics\n";

    if (use_metrics && daemon_mode) {
        std::cout << "\n[Metrics] Daemon mode active. Keeping metrics server online. Press Ctrl+C to exit.\n";
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    if (use_metrics) metrics.stop();

    LOG_INFO << "NetScope DPI Lite finished.";
    return 0;
}
