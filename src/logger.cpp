#include "mw/logger.hpp"
#include<atomic>
#include<chrono>
#include<cstdio>
#include<ctime>
#include<mutex>
#include<sstream>
#include<string>
#include<thread>

namespace mw {
namespace {

std::atomic<LogLevel> g_level{LogLevel::Info};

const char* level_name(LogLevel level) {
  switch (level) {
  case LogLevel::Debug: return "DEBUG";
  case LogLevel::Info: return "INFO";
  case LogLevel::Warn: return "WARN";
  case LogLevel::Error: return "ERROR";
  }
  return "?";
}

} // namespace

void set_log_level(LogLevel level) {
  g_level.store(level, std::memory_order_relaxed);
}

LogLevel log_level() {
  return g_level.load(std::memory_order_relaxed);
}

void log_line(LogLevel level, std::string_view message) {
  static std::mutex mutex;

  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#ifdef _WIN32
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;

  std::ostringstream tid;
  tid << std::this_thread::get_id();

  std::string line = std::format("[{:02}:{:02}:{:02}.{:03}][{}][{}] {}\n", tm.tm_hour, tm.tm_min, tm.tm_sec, ms, level_name(level), tid.str(), message);

  std::lock_guard<std::mutex> lock(mutex);
  std::fputs(line.c_str(), stderr);
}

} // namespace mw
