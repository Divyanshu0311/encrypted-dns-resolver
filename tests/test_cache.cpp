#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

#include "DomainName.hpp"
#include "Records.hpp"
#include "backend/Cache.hpp"
#include "support/temp_dir.hpp"

namespace {
    using types::DomainName;
    using types::RecordClass;
    using types::RecordType;
    using types::ResourceRecord;

    // time only moves when the test says so
    struct FakeTime {
        std::shared_ptr<std::atomic<std::time_t>> now = std::make_shared<std::atomic<std::time_t>>(1'000'000);
        backend::Cache::Clock clock() const {
            return [now = now] { return now->load(); };
        }
        void advance(std::time_t seconds) { *now += seconds; }
    };

    ResourceRecord a(const std::string& name, uint8_t last, uint32_t ttl = 60) {
        return ResourceRecord{ DomainName(name), RecordType::A, RecordClass::IN, ttl, { 192, 0, 2, last } };
    }

    ResourceRecord cname(const std::string& name, const std::string& target, uint32_t ttl = 60) {
        return ResourceRecord{ DomainName(name), RecordType::CNAME, RecordClass::IN, ttl, static_cast<std::vector<uint8_t>>(DomainName(target)) };
    }
} // namespace

TEST(Cache, FindsWhatWasStored) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    EXPECT_TRUE(cache.update({ a("example.com.", 1), a("example.com.", 2) }));

    const auto found = cache.find(DomainName("EXAMPLE.com."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[0].rdata, (std::vector<uint8_t>{ 192, 0, 2, 1 }));
    EXPECT_TRUE(cache.find(DomainName("example.com."), RecordType::AAAA, RecordClass::IN).empty());
    EXPECT_TRUE(cache.find(DomainName("other.com."), RecordType::A, RecordClass::IN).empty());
}

TEST(Cache, TtlCountsDownAndExpires) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ a("example.com.", 1, 60) });

    time.advance(20);
    auto found = cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].ttl, 40u);

    time.advance(40);
    EXPECT_TRUE(cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN).empty());
}

TEST(Cache, RrsetSharesItsLowestTtl) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ a("example.com.", 1, 300), a("example.com.", 2, 30) });
    time.advance(31);
    EXPECT_TRUE(cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN).empty());
}

TEST(Cache, UpdateReplacesTheWholeRrset) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ a("example.com.", 1), a("example.com.", 2) });
    cache.update({ a("example.com.", 3) });
    const auto found = cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].rdata[3], 3);
}

TEST(Cache, ZeroTtlIsNotStored) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    EXPECT_FALSE(cache.update({ a("example.com.", 1, 0) }));
    EXPECT_TRUE(cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN).empty());
}

TEST(Cache, FindAnswerFollowsCnames) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ cname("www.example.com.", "cdn.example.net."), cname("cdn.example.net.", "edge.example.org."), a("edge.example.org.", 7) });

    const auto answer = cache.find_answer(DomainName("www.example.com."), RecordType::A, RecordClass::IN);
    ASSERT_TRUE(answer.has_value());
    EXPECT_EQ(answer->served_by, "cache");
    ASSERT_EQ(answer->answer.size(), 3u);
    EXPECT_EQ(answer->answer[0].type, RecordType::CNAME);
    EXPECT_EQ(answer->answer[2].rdata[3], 7);

    // the chain is only an answer if it ends in the type asked for
    EXPECT_FALSE(cache.find_answer(DomainName("www.example.com."), RecordType::AAAA, RecordClass::IN).has_value());
    // asking for the CNAME itself stops at the first hop
    const auto just_cname = cache.find_answer(DomainName("www.example.com."), RecordType::CNAME, RecordClass::IN);
    ASSERT_TRUE(just_cname.has_value());
    EXPECT_EQ(just_cname->answer.size(), 1u);
}

TEST(Cache, CnameLoopIsNotAnAnswer) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ cname("a.example.", "b.example."), cname("b.example.", "a.example.") });
    EXPECT_FALSE(cache.find_answer(DomainName("a.example."), RecordType::A, RecordClass::IN).has_value());
}

TEST(Cache, CountsHitsAndMisses) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ a("example.com.", 1) });
    (void)cache.find_answer(DomainName("example.com."), RecordType::A, RecordClass::IN);
    (void)cache.find_answer(DomainName("example.com."), RecordType::A, RecordClass::IN);
    (void)cache.find_answer(DomainName("missing.com."), RecordType::A, RecordClass::IN);
    const auto stats = cache.stats();
    EXPECT_EQ(stats.hits, 2u);
    EXPECT_EQ(stats.misses, 1u);
    EXPECT_EQ(stats.rrsets, 1u);
    EXPECT_EQ(stats.records, 1u);
}

TEST(Cache, FullCacheDropsExpiredThenEverything) {
    FakeTime time;
    backend::Cache cache(3, time.clock());
    cache.update({ a("one.example.", 1, 10), a("two.example.", 2, 100), a("three.example.", 3, 100) });
    time.advance(11);
    // one.example. has expired, so it makes room
    cache.update({ a("four.example.", 4, 100) });
    EXPECT_EQ(cache.stats().records, 3u);
    EXPECT_FALSE(cache.find(DomainName("two.example."), RecordType::A, RecordClass::IN).empty());

    // nothing expired: everything goes rather than growing past the limit
    cache.update({ a("five.example.", 5, 100) });
    EXPECT_EQ(cache.stats().records, 1u);
    EXPECT_FALSE(cache.find(DomainName("five.example."), RecordType::A, RecordClass::IN).empty());
}

TEST(Cache, RootHintsAreKeptForever) {
    support::TempDir dir;
    const auto file = dir.write("named.root", ".  3600000  IN  NS  a.root-servers.net.\n"
                                              "a.root-servers.net.  3600000  IN  A  198.41.0.4\n");
    FakeTime time;
    backend::Cache cache(100, time.clock());
    ASSERT_TRUE(cache.add_root_hints(file));

    time.advance(10'000'000);
    EXPECT_EQ(cache.find(DomainName("."), RecordType::NS, RecordClass::IN).size(), 1u);
    // answers never replace them, and clear() leaves them alone
    cache.update({ a("a.root-servers.net.", 66) });
    cache.clear();
    const auto root = cache.find(DomainName("a.root-servers.net."), RecordType::A, RecordClass::IN);
    ASSERT_EQ(root.size(), 1u);
    EXPECT_EQ(root[0].rdata, (std::vector<uint8_t>{ 198, 41, 0, 4 }));
}

TEST(Cache, MissingRootHintsFileIsFalse) {
    backend::Cache cache;
    EXPECT_FALSE(cache.add_root_hints("/nonexistent/named.root"));
}

TEST(Cache, ClearEmptiesIt) {
    FakeTime time;
    backend::Cache cache(100, time.clock());
    cache.update({ a("example.com.", 1) });
    cache.clear();
    EXPECT_TRUE(cache.find(DomainName("example.com."), RecordType::A, RecordClass::IN).empty());
    EXPECT_EQ(cache.stats().records, 0u);
}
