#pragma once
#include<cstdint>
#include<format>
#include<string_view>
#include<utility>

// Will hold: mw logging (thread safe, writes to stderr)

namespace mw {

enum class LogLevel : uint8_t {
  Debug,
  Info,
  Warn,
  Error
};

void set_log_level(LogLevel level);
LogLevel log_level();

// writes one line: [HH:MM:SS.mmm][LEVEL][tid] message
void log_line(LogLevel level, std::string_view message);

template<class... Args>
void log(LogLevel lvl, std::format_string<Args...> fmt, Args&&... args) {
  if (lvl < log_level())
    return; // don't pay for formatting a line nobody sees
  log_line(lvl, std::format(fmt, std::forward<Args>(args)...));
}

template<class... Args>
void debug(std::format_string<Args...> fmt, Args&&... args) { log(LogLevel::Debug, fmt, std::forward<Args>(args)...); }

template<class... Args>
void info(std::format_string<Args...> fmt, Args&&... args) { log(LogLevel::Info, fmt, std::forward<Args>(args)...); }

template<class... Args>
void warn(std::format_string<Args...> fmt, Args&&... args) { log(LogLevel::Warn, fmt, std::forward<Args>(args)...); }

template<class... Args>
void error(std::format_string<Args...> fmt, Args&&... args) { log(LogLevel::Error, fmt, std::forward<Args>(args)...); }

} // namespace mw
