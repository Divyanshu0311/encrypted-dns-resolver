#include "mw/query_log.hpp"

#include "support/show.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

mw::QueryLogEntry entry(const std::string& name) {
  mw::QueryLogEntry e;
  e.name = name;
  return e;
}

} // namespace

TEST(QueryLog, NumbersEntriesInOrder) {
  mw::QueryLog log;
  log.add(entry("a."));
  log.add(entry("b."));
  const auto all = log.since(0);
  ASSERT_SHOW_EQ(all.size(), 2u);
  EXPECT_SHOW_EQ(all[0].seq, 1u);
  EXPECT_SHOW_EQ(all[1].name, std::string("b."));
  ASSERT_SHOW_EQ(log.since(1).size(), 1u);
  EXPECT_SHOW_EQ(log.since(2).size(), 0u);
}

TEST(QueryLog, OldestEntriesDropOff) {
  mw::QueryLog log(3);
  for (const char* n : {"a.", "b.", "c.", "d."})
    log.add(entry(n));
  const auto all = log.since(0);
  ASSERT_SHOW_EQ(all.size(), 3u);
  EXPECT_SHOW_EQ(all[0].name, std::string("b."));
  EXPECT_SHOW_EQ(all[0].seq, 2u);
}

TEST(QueryLog, LimitKeepsTheNewest) {
  mw::QueryLog log;
  for (int i = 0; i < 10; i++)
    log.add(entry("n."));
  const auto some = log.since(0, 4);
  ASSERT_SHOW_EQ(some.size(), 4u);
  EXPECT_SHOW_EQ(some[0].seq, 7u);
}

TEST(QueryLog, KeepsOnlyTheFirstAnswers) {
  mw::QueryLog log;
  auto e = entry("many.");
  e.answer.resize(10, mw::ResourceRecord{mw::DomainName("many."), mw::RecordType::A, mw::RecordClass::IN, 1, {1, 2, 3, 4}});
  log.add(std::move(e));
  EXPECT_SHOW_EQ(log.since(0)[0].answer.size(), mw::QueryLog::kAnswersKept);
}
