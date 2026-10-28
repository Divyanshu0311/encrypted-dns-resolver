#include "mw/tls_context.hpp"

#include "support/show.hpp"
#include "support/temp_dir.hpp"
#include "support/tls_cert.hpp"

#include <gtest/gtest.h>

#include <openssl/ssl.h>

#include <string>
#include <vector>

namespace {

    struct Handshake {
        bool ok     = false;
        int version = 0;
        std::string alpn;
    };

    // both ends in memory over a BIO pair, no sockets
    Handshake handshake(SSL_CTX* server_ctx, int client_max_version, const std::vector<unsigned char>& client_alpn = {}) {
        SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(client_ctx, client_max_version);
        SSL* client = SSL_new(client_ctx);
        SSL* server = SSL_new(server_ctx);
        if (!client_alpn.empty()) {
            SSL_set_alpn_protos(client, client_alpn.data(), static_cast<unsigned int>(client_alpn.size()));
        }
        BIO* client_bio = nullptr;
        BIO* server_bio = nullptr;
        BIO_new_bio_pair(&client_bio, 0, &server_bio, 0);
        SSL_set_bio(client, client_bio, client_bio);
        SSL_set_bio(server, server_bio, server_bio);
        SSL_set_connect_state(client);
        SSL_set_accept_state(server);

        Handshake result;
        bool client_done = false;
        bool server_done = false;
        for (int round = 0; round < 50 && !(client_done && server_done); ++round) {
            if (!client_done) {
                const int r = SSL_do_handshake(client);
                client_done = r == 1;
                if (r <= 0 && SSL_get_error(client, r) != SSL_ERROR_WANT_READ) {
                    break;
                }
            }
            if (!server_done) {
                const int r = SSL_do_handshake(server);
                server_done = r == 1;
                if (r <= 0 && SSL_get_error(server, r) != SSL_ERROR_WANT_READ) {
                    break;
                }
            }
        }
        result.ok = client_done && server_done;
        if (result.ok) {
            result.version            = SSL_version(server);
            const unsigned char* alpn = nullptr;
            unsigned int alpn_length  = 0;
            SSL_get0_alpn_selected(server, &alpn, &alpn_length);
            result.alpn.assign(reinterpret_cast<const char*>(alpn), alpn_length);
        }
        SSL_free(client);
        SSL_free(server);
        SSL_CTX_free(client_ctx);
        return result;
    }

} // namespace

TEST(TlsContext, LoadsAMatchingCertAndKey) {
    support::TempDir dir;
    const auto cert    = mw::test::make_test_cert(dir);
    const auto context = mw::TlsContext::create(cert.cert, cert.key);
    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_NE(context->get(), nullptr);
}

TEST(TlsContext, MissingFilesAreErrors) {
    support::TempDir dir;
    const auto cert           = mw::test::make_test_cert(dir);
    const std::string missing = (dir.path() / "nope.pem").string();

    const auto no_cert = mw::TlsContext::create(missing, cert.key);
    ASSERT_FALSE(no_cert.has_value());
    EXPECT_SHOW_EQ(no_cert.error().rfind("tls_cert '" + missing + "'", 0), 0u);

    const auto no_key = mw::TlsContext::create(cert.cert, missing);
    ASSERT_FALSE(no_key.has_value());
    EXPECT_SHOW_EQ(no_key.error().rfind("tls_key '" + missing + "'", 0), 0u);
}

TEST(TlsContext, KeyFromAnotherCertIsAnError) {
    support::TempDir dir;
    const auto first   = mw::test::make_test_cert(dir, "first");
    const auto second  = mw::test::make_test_cert(dir, "second");
    const auto context = mw::TlsContext::create(first.cert, second.key);
    ASSERT_FALSE(context.has_value());
    EXPECT_NE(context.error().find("does not match"), std::string::npos) << context.error();
}

TEST(TlsContext, Tls13HandshakeSucceeds) {
    support::TempDir dir;
    const auto cert    = mw::test::make_test_cert(dir);
    const auto context = mw::TlsContext::create(cert.cert, cert.key);
    ASSERT_TRUE(context.has_value()) << context.error();
    const auto result = handshake(context->get(), TLS1_3_VERSION);
    EXPECT_SHOW_EQ(result.ok, true);
    EXPECT_SHOW_EQ(result.version, TLS1_3_VERSION);
}

TEST(TlsContext, Tls12ClientIsRejected) {
    support::TempDir dir;
    const auto cert    = mw::test::make_test_cert(dir);
    const auto context = mw::TlsContext::create(cert.cert, cert.key);
    ASSERT_TRUE(context.has_value()) << context.error();
    EXPECT_SHOW_EQ(handshake(context->get(), TLS1_2_VERSION).ok, false);
}

TEST(TlsContext, SelectsDotWhenOffered) {
    support::TempDir dir;
    const auto cert    = mw::test::make_test_cert(dir);
    const auto context = mw::TlsContext::create(cert.cert, cert.key);
    ASSERT_TRUE(context.has_value()) << context.error();

    const std::vector<unsigned char> h2_and_dot = { 2, 'h', '2', 3, 'd', 'o', 't' };
    const auto offered                          = handshake(context->get(), TLS1_3_VERSION, h2_and_dot);
    EXPECT_SHOW_EQ(offered.ok, true);
    EXPECT_SHOW_EQ(offered.alpn, "dot");

    const auto not_offered = handshake(context->get(), TLS1_3_VERSION, { 2, 'h', '2' });
    EXPECT_SHOW_EQ_AS("other ALPN only: still connects", not_offered.ok, true);
    EXPECT_SHOW_EQ(not_offered.alpn, "");

    const auto none = handshake(context->get(), TLS1_3_VERSION);
    EXPECT_SHOW_EQ_AS("no ALPN at all", none.ok, true);
}
