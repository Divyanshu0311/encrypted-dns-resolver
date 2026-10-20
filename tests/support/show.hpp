#pragma once

// EXPECT_SHOW_EQ / EXPECT_SHOW_NE (and ASSERT_ variants) behave like EXPECT_EQ / EXPECT_NE but
// record every check's expected and actual values, passed or failed, for the printer in
// tests/main.cpp. The _AS variants take a label to show instead of the actual expression.

#include "printers.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace mw::test {

struct Check {
  bool ok;
  std::string label;
  std::string expected;
  std::string actual;
  std::string where; // "file:line", filled in by the printer on failure
  bool raw = false;  // a plain gtest failure; `label` holds its message
};

// Checks made by the running test; cleared by the printer when each test starts.
inline std::vector<Check>& checks() {
  static std::vector<Check> all;
  return all;
}

// Shows a string in full when short; otherwise its head, tail and length.
inline std::string describe(const std::string& s) {
  if (s.size() <= 32) {
    return ::testing::PrintToString(s);
  }
  std::string head = ::testing::PrintToString(s.substr(0, 10));
  std::string tail = ::testing::PrintToString(s.substr(s.size() - 8));
  head.pop_back();
  tail.erase(0, 1);
  return head + "…" + tail + " [" + std::to_string(s.size()) + " bytes]";
}

inline std::string tidy(std::string expr) {
  for (auto pos = expr.find("mw::"); pos != std::string::npos; pos = expr.find("mw::", pos)) {
    expr.erase(pos, 4);
  }
  return expr;
}

inline ::testing::AssertionResult record(bool ok, std::string label, std::string expected,
                                         std::string actual) {
  checks().push_back({ok, label, expected, actual, {}, false});
  if (ok) {
    return ::testing::AssertionSuccess();
  }
  return ::testing::AssertionFailure() << label << "\n  expected: " << expected
                                       << "\n  actual:   " << actual;
}

template <typename Actual, typename Expected>
::testing::AssertionResult show_eq(const char* actual_expr, const char* /*expected_expr*/,
                                   const Actual& actual, const Expected& expected) {
  return record(actual == expected, tidy(actual_expr), ::testing::PrintToString(expected),
                ::testing::PrintToString(actual));
}

template <typename Actual, typename Expected>
::testing::AssertionResult show_ne(const char* actual_expr, const char* /*expected_expr*/,
                                   const Actual& actual, const Expected& expected) {
  return record(actual != expected, tidy(actual_expr), "!= " + ::testing::PrintToString(expected),
                ::testing::PrintToString(actual));
}

template <typename Label, typename Actual, typename Expected>
::testing::AssertionResult show_eq_as(const char*, const char*, const char*, const Label& label,
                                      const Actual& actual, const Expected& expected) {
  return record(actual == expected, std::string(label), ::testing::PrintToString(expected),
                ::testing::PrintToString(actual));
}

template <typename Label, typename Actual, typename Expected>
::testing::AssertionResult show_ne_as(const char*, const char*, const char*, const Label& label,
                                      const Actual& actual, const Expected& expected) {
  return record(actual != expected, std::string(label), "!= " + ::testing::PrintToString(expected),
                ::testing::PrintToString(actual));
}

} // namespace mw::test

#define EXPECT_SHOW_EQ(actual, expected) EXPECT_PRED_FORMAT2(::mw::test::show_eq, actual, expected)
#define EXPECT_SHOW_NE(actual, expected) EXPECT_PRED_FORMAT2(::mw::test::show_ne, actual, expected)
#define ASSERT_SHOW_EQ(actual, expected) ASSERT_PRED_FORMAT2(::mw::test::show_eq, actual, expected)
#define ASSERT_SHOW_NE(actual, expected) ASSERT_PRED_FORMAT2(::mw::test::show_ne, actual, expected)

#define EXPECT_SHOW_EQ_AS(label, actual, expected)                                                 \
  EXPECT_PRED_FORMAT3(::mw::test::show_eq_as, label, actual, expected)
#define EXPECT_SHOW_NE_AS(label, actual, expected)                                                 \
  EXPECT_PRED_FORMAT3(::mw::test::show_ne_as, label, actual, expected)
#define ASSERT_SHOW_EQ_AS(label, actual, expected)                                                 \
  ASSERT_PRED_FORMAT3(::mw::test::show_eq_as, label, actual, expected)
#define ASSERT_SHOW_NE_AS(label, actual, expected)                                                 \
  ASSERT_PRED_FORMAT3(::mw::test::show_ne_as, label, actual, expected)
