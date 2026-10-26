#include "mw/inflight_table.hpp"

#include "support/fakes.hpp"
#include "support/show.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace {

mw::QueryKey key(const std::string& name, mw::RecordType type = mw::RecordType::A) {
  return mw::QueryKey{mw::DomainName(name), type};
}

std::shared_ptr<mw::Responder> responder(mw::Metrics& metrics, const mw::QueryKey& k) {
  return std::make_shared<mw::Responder>(k, mw::ClientInfo{}, [](mw::ResolveResult) {}, mw::SteadyClock::now(), metrics,
                                         mw::steady_clock_fn());
}

} // namespace

TEST(InFlightTable, FirstAttachLeadsOthersFollow) {
  mw::Metrics metrics;
  mw::InFlightTable table;
  const auto k = key("example.com.");
  auto a = responder(metrics, k);
  auto b = responder(metrics, k);
  auto c = responder(metrics, k);

  EXPECT_SHOW_EQ(table.attach(k, a), true);
  EXPECT_SHOW_EQ(table.attach(k, b), false);
  EXPECT_SHOW_EQ(table.attach(k, c), false);
  EXPECT_SHOW_EQ(table.size(), 1u);

  const auto waiters = table.take(k);
  ASSERT_SHOW_EQ(waiters.size(), 3u);
  EXPECT_SHOW_EQ(waiters[0].get(), a.get());
  EXPECT_SHOW_EQ(waiters[1].get(), b.get());
  EXPECT_SHOW_EQ(waiters[2].get(), c.get());
  EXPECT_SHOW_EQ(table.size(), 0u);
}

TEST(InFlightTable, TakeMissingKeyIsEmpty) {
  mw::InFlightTable table;
  EXPECT_SHOW_EQ(table.take(key("nothing.test.")).size(), 0u);
}

TEST(InFlightTable, CaseInsensitiveKeysCoalesce) {
  mw::Metrics metrics;
  mw::InFlightTable table;
  EXPECT_SHOW_EQ(table.attach(key("example.com."), responder(metrics, key("example.com."))), true);
  EXPECT_SHOW_EQ(table.attach(key("EXAMPLE.Com."), responder(metrics, key("EXAMPLE.Com."))), false);
  EXPECT_SHOW_EQ(table.size(), 1u);
}

TEST(InFlightTable, DifferentTypesAreSeparateEntries) {
  mw::Metrics metrics;
  mw::InFlightTable table;
  EXPECT_SHOW_EQ(table.attach(key("example.com.", mw::RecordType::A), responder(metrics, key("example.com."))), true);
  EXPECT_SHOW_EQ(table.attach(key("example.com.", mw::RecordType::AAAA), responder(metrics, key("example.com."))), true);
  EXPECT_SHOW_EQ(table.size(), 2u);
  EXPECT_SHOW_EQ(table.take(key("example.com.", mw::RecordType::A)).size(), 1u);
  EXPECT_SHOW_EQ(table.size(), 1u);
}

TEST(InFlightTable, TakeAllEmptiesTable) {
  mw::Metrics metrics;
  mw::InFlightTable table;
  table.attach(key("a.test."), responder(metrics, key("a.test.")));
  table.attach(key("a.test."), responder(metrics, key("a.test.")));
  table.attach(key("b.test."), responder(metrics, key("b.test.")));
  EXPECT_SHOW_EQ(table.take_all().size(), 3u);
  EXPECT_SHOW_EQ(table.size(), 0u);
  EXPECT_SHOW_EQ(table.take_all().size(), 0u);
}
