#pragma once
// ============================================================================
// logger.h — Thread-safe timestamped logger
// NetScope DPI Lite (NEW — not in original repo)
// ============================================================================

#include <string>
#include <fstream>
#include <mutex>
#include <sstream>
#include <chrono>
#include <ctime>
#include <iostream>

namespace NetScope {

enum class LogLevel { DEBUG, INFO, WARN, ERR };

class Logger {
public:
    // Singleton
    static Logger& instance();

    // Configure before use
    void init(const std::string& log_file, LogLevel min_level = LogLevel::INFO);

    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
    void info (const std::string& msg) { log(LogLevel::INFO,  msg); }
    void warn (const std::string& msg) { log(LogLevel::WARN,  msg); }
    void error(const std::string& msg) { log(LogLevel::ERR, msg); }

    void log(LogLevel level, const std::string& msg);

    // RAII helper for stream-style logging:
    // LOG_INFO << "Processed " << n << " packets";
    struct Stream {
        Logger&  logger;
        LogLevel level;
        std::ostringstream ss;

        Stream(Logger& l, LogLevel lv) : logger(l), level(lv) {}

        // Must be moveable (ostringstream is non-copyable)
        Stream(Stream&&) = default;
        Stream(const Stream&) = delete;
        Stream& operator=(const Stream&) = delete;

        ~Stream() { logger.log(level, ss.str()); }

        template<typename T>
        Stream& operator<<(const T& v) { ss << v; return *this; }
    };

    Stream makeStream(LogLevel level) { return Stream(*this, level); }

private:
    Logger() = default;
    mutable std::mutex mutex_;
    std::ofstream      file_;
    LogLevel           min_level_ = LogLevel::INFO;

    static const char* levelStr(LogLevel l);
    static std::string timestamp();
};

// Convenience macros
#define LOG_DEBUG NetScope::Logger::instance().makeStream(NetScope::LogLevel::DEBUG)
#define LOG_INFO  NetScope::Logger::instance().makeStream(NetScope::LogLevel::INFO)
#define LOG_WARN  NetScope::Logger::instance().makeStream(NetScope::LogLevel::WARN)
#define LOG_ERROR NetScope::Logger::instance().makeStream(NetScope::LogLevel::ERR)

} // namespace NetScope
