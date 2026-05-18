// ============================================================================
// logger.cpp — Thread-safe logger implementation
// NetScope DPI Lite
// ============================================================================

#include "logger.h"
#include <iomanip>
#include <ctime>
#include <cstring>

namespace NetScope {

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::init(const std::string& log_file, LogLevel min_level) {
    std::lock_guard<std::mutex> lock(mutex_);
    min_level_ = min_level;
    if (!log_file.empty()) {
        file_.open(log_file, std::ios::app);
        if (!file_.is_open()) {
            std::cerr << "[Logger] Warning: cannot open log file: " << log_file << '\n';
        }
    }
}

void Logger::log(LogLevel level, const std::string& msg) {
    if (level < min_level_) return;

    std::string line = "[" + timestamp() + "] [" + levelStr(level) + "] " + msg;

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << line << '\n';
    if (file_.is_open()) {
        file_ << line << '\n';
        file_.flush();
    }
}

const char* Logger::levelStr(LogLevel l) {
    switch (l) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERR:   return "ERROR";
        default:              return "?????";
    }
}

std::string Logger::timestamp() {
    auto now     = std::chrono::system_clock::now();
    auto time_t_ = std::chrono::system_clock::to_time_t(now);
    auto ms      = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;

    // localtime is portable across MinGW, Linux, and MSVC
    // (no thread safety needed — timestamp() is only called inside log() which holds mutex_)
    std::tm* tm_ptr = std::localtime(&time_t_);
    std::tm  tm_buf = (tm_ptr ? *tm_ptr : std::tm{});

    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    std::ostringstream ss;
    ss << buf << '.' << std::setw(3) << std::setfill('0') << ms.count();
    return ss.str();
}

} // namespace NetScope
