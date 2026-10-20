// Test entry point. Replaces gtest's default output with a compact printer that shows each
// check's expected and actual values, green when it passes and red when it fails.
// Colour follows --gtest_color (auto: only when stdout is a terminal).

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using mw::test::Check;

constexpr const char* kGreen = "\033[32m";
constexpr const char* kRed = "\033[31m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kBold = "\033[1m";
constexpr const char* kDim = "\033[2m";
constexpr const char* kReset = "\033[0m";

bool use_color() {
  const std::string flag = ::testing::GTEST_FLAG(color);
  if (flag == "yes" || flag == "true" || flag == "t" || flag == "1") {
    return true;
  }
  if (flag != "auto") {
    return false;
  }
  const char* term = std::getenv("TERM");
  return isatty(STDOUT_FILENO) != 0 && term != nullptr && std::strcmp(term, "dumb") != 0;
}

std::size_t terminal_width() {
  winsize ws{};
  if (isatty(STDOUT_FILENO) != 0 && ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
    return ws.ws_col;
  }
  return 120;
}

// Display width of UTF-8 text: counts every byte except continuation bytes.
std::size_t width(std::string_view s) {
  return static_cast<std::size_t>(
      std::count_if(s.begin(), s.end(), [](char c) { return (c & 0xC0) != 0x80; }));
}

std::string pad(std::string s, std::size_t w) {
  const std::size_t n = width(s);
  if (n < w) {
    s.append(w - n, ' ');
  }
  return s;
}

std::string spaces(std::size_t n) {
  return std::string(n, ' ');
}

// Parameterized tests are named "<test>/<case>"; the case name is the useful part.
std::string display_name(const ::testing::TestInfo& info) {
  std::string name = info.name();
  if (info.value_param() != nullptr) {
    name = name.substr(name.rfind('/') + 1);
  }
  return name;
}

struct Row {
  std::string name;
  const char* tone;
  std::string mark;
  std::vector<Check> checks;
};

// Column widths shared by every line of a suite.
struct Widths {
  std::size_t name = 0;
  std::size_t label = 0;
  std::size_t expected = 0;
  std::size_t actual = 0;
};

std::string values(const Check& c, std::size_t expected_width) {
  return "expected: " + pad(c.expected, expected_width) + "  actual: " + c.actual;
}

// Results are buffered per suite so every line of a suite can share one aligned layout:
//
//   flat     one line per test        ✓ Name   label   expected: x   actual: y
//   stacked  name + label, values below
//   blocks   name, then one line per check
//   blocks, stacked                   name, then each check's label with values below
//
// The first layout that fits the terminal is used; tests with several checks always use blocks.
class PrettyPrinter : public ::testing::EmptyTestEventListener {
public:
  PrettyPrinter() : color_(use_color()), columns_(terminal_width()) {}

  void OnTestIterationStart(const ::testing::UnitTest& unit, int) override {
    print(kBold, "Running " + std::to_string(unit.test_to_run_count()) + " tests from " +
                     std::to_string(unit.test_suite_to_run_count()) + " suites");
  }

  void OnTestSuiteStart(const ::testing::TestSuite& suite) override {
    rows_.clear();
    std::cout << "\n";
    print(kBold, suite.name());
  }

  void OnTestStart(const ::testing::TestInfo&) override { mw::test::checks().clear(); }

  void OnTestPartResult(const ::testing::TestPartResult& result) override {
    if (!result.failed()) {
      return;
    }
    const std::string where = std::string(result.file_name() ? result.file_name() : "?") + ":" +
                              std::to_string(result.line_number());
    auto& checks = mw::test::checks();
    if (!checks.empty() && !checks.back().ok && checks.back().where.empty()) {
      checks.back().where = where;
      return;
    }
    checks.push_back({false, result.message(), "", "", where, true});
  }

  void OnTestEnd(const ::testing::TestInfo& info) override {
    const auto* result = info.result();
    Row row{display_name(info), kGreen, "✓", mw::test::checks()};
    if (result->Skipped()) {
      row.tone = kYellow;
      row.mark = "-";
      row.name += "  (skipped)";
    } else if (!result->Passed()) {
      row.tone = kRed;
      row.mark = "✗";
      failed_.push_back(std::string(info.test_suite_name()) + "." + info.name());
    }
    rows_.push_back(std::move(row));
  }

  void OnTestSuiteEnd(const ::testing::TestSuite&) override {
    // Checks whose values can never share a line are always printed one value per line and
    // are left out of the column widths so they don't stretch everything else.
    Widths w;
    bool one_check_each = true;
    bool any_too_long = false;
    std::size_t widest_label = 0;
    for (const auto& row : rows_) {
      w.name = std::max(w.name, width(row.name));
      one_check_each = one_check_each && row.checks.size() <= 1;
      for (const auto& c : row.checks) {
        one_check_each = one_check_each && !c.raw;
        if (c.raw) {
          continue;
        }
        widest_label = std::max(widest_label, width(c.label));
        if (too_long(c)) {
          any_too_long = true;
          continue;
        }
        w.label = std::max(w.label, width(c.label));
        w.expected = std::max(w.expected, width(c.expected));
        w.actual = std::max(w.actual, width(c.actual));
      }
    }
    const std::size_t values_width = 10 + w.expected + 10 + w.actual;

    if (one_check_each) {
      const std::size_t label_col = 4 + w.name + 3;
      if (!any_too_long && label_col + w.label + 2 + values_width <= columns_) {
        print_flat(w, label_col);
      } else if (label_col + widest_label <= columns_) {
        print_stacked(w, label_col);
      } else {
        print_blocks(w, false);
      }
    } else {
      print_blocks(w, 8 + w.label + 2 + values_width <= columns_);
    }
  }

  void OnTestIterationEnd(const ::testing::UnitTest& unit, int) override {
    std::cout << "\n";
    std::string summary = std::to_string(unit.successful_test_count()) + " passed";
    if (unit.skipped_test_count() > 0) {
      summary += ", " + std::to_string(unit.skipped_test_count()) + " skipped";
    }
    if (unit.failed_test_count() > 0) {
      summary += ", " + std::to_string(unit.failed_test_count()) + " failed";
    }
    summary += "  (" + std::to_string(unit.elapsed_time()) + " ms)";
    print(unit.failed_test_count() > 0 ? kRed : kGreen, summary);
    for (const auto& name : failed_) {
      print(kRed, "  ✗ " + name);
    }
  }

private:
  std::string head(const Row& row) const { return "  " + row.mark + " " + row.name; }

  void print_flat(const Widths& w, std::size_t label_col) const {
    for (const auto& row : rows_) {
      if (row.checks.empty()) {
        print(row.tone, head(row));
        continue;
      }
      const Check& c = row.checks[0];
      print(row.tone, pad(head(row), label_col) + pad(c.label, w.label) + "  " +
                          values(c, w.expected));
      print_where(c, label_col);
    }
  }

  void print_stacked(const Widths& w, std::size_t label_col) const {
    for (const auto& row : rows_) {
      if (row.checks.empty()) {
        print(row.tone, head(row));
        continue;
      }
      const Check& c = row.checks[0];
      print(row.tone, pad(head(row), label_col) + c.label);
      print_values(c, row.tone, label_col, w.expected);
      print_where(c, label_col);
    }
  }

  void print_blocks(const Widths& w, bool one_line) const {
    for (const auto& row : rows_) {
      print(row.tone, head(row));
      for (const auto& c : row.checks) {
        const char* tone = c.ok ? kGreen : kRed;
        const std::string mark = spaces(6) + (c.ok ? "✓ " : "✗ ");
        if (c.raw) {
          std::string message = c.label;
          for (auto pos = message.find('\n'); pos != std::string::npos;
               pos = message.find('\n', pos + 1)) {
            message.insert(pos + 1, spaces(8));
          }
          print(tone, mark + message);
        } else if (one_line && !too_long(c)) {
          print(tone, mark + pad(c.label, w.label) + "  " + values(c, w.expected));
        } else {
          print(tone, mark + c.label);
          print_values(c, tone, 10, w.expected);
        }
        print_where(c, 8);
      }
    }
  }

  bool too_long(const Check& c) const {
    constexpr std::size_t kMaxInlineValue = 30;
    return width(c.expected) > kMaxInlineValue || width(c.actual) > kMaxInlineValue ||
           10 + width(values(c, 0)) > columns_;
  }

  // "expected: x  actual: y" on one line when it fits, else one value per line.
  void print_values(const Check& c, const char* tone, std::size_t indent,
                    std::size_t expected_width) const {
    if (!too_long(c) && indent + width(values(c, expected_width)) <= columns_) {
      print(tone, spaces(indent) + values(c, expected_width));
    } else {
      print(tone, spaces(indent) + "expected: " + c.expected);
      print(tone, spaces(indent) + "actual:   " + c.actual);
    }
  }

  void print_where(const Check& c, std::size_t indent) const {
    if (!c.where.empty()) {
      print(kDim, spaces(indent) + "at " + c.where);
    }
  }

  void print(const char* tone, const std::string& text) const {
    if (color_) {
      std::cout << tone << text << kReset << "\n";
    } else {
      std::cout << text << "\n";
    }
  }

  bool color_;
  std::size_t columns_;
  std::vector<Row> rows_;
  std::vector<std::string> failed_;
};

} // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  auto& listeners = ::testing::UnitTest::GetInstance()->listeners();
  delete listeners.Release(listeners.default_result_printer());
  listeners.Append(new PrettyPrinter);
  return RUN_ALL_TESTS();
}
