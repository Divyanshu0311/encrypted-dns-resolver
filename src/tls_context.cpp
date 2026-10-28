#include "mw/tls_context.hpp"

#include <cstring>
#include <format>
#include <system_error>

#include <openssl/err.h>
#include <openssl/x509.h>

#include "mw/logger.hpp"

namespace mw {
    namespace {

        // the client's ALPN list is a series of length-prefixed names
        int select_alpn(SSL*, const unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen, void*) {
            for (unsigned int i = 0; i < inlen;) {
                const unsigned int length = in[i];
                if (i + 1 + length > inlen) {
                    break;
                }
                if (length == 3 && std::memcmp(in + i + 1, "dot", 3) == 0) {
                    *out    = in + i + 1;
                    *outlen = 3;
                    return SSL_TLSEXT_ERR_OK;
                }
                i += 1 + length;
            }
            return SSL_TLSEXT_ERR_NOACK; // no "dot" on offer: carry on without ALPN
        }

        void warn_if_key_is_readable(const std::filesystem::path& key) {
            using std::filesystem::perms;
            std::error_code ec;
            const auto mode = std::filesystem::status(key, ec).permissions();
            if (!ec && (mode & (perms::group_all | perms::others_all)) != perms::none) {
                warn("tls_key '{}' can be read by other users, chmod 600 it", key.string());
            }
        }

    } // namespace

    std::string openssl_errors() {
        std::string text;
        while (const unsigned long code = ERR_get_error()) {
            char buf[256];
            ERR_error_string_n(code, buf, sizeof buf);
            if (!text.empty()) {
                text += "; ";
            }
            text += buf;
        }
        return text.empty() ? "unknown error" : text;
    }

    std::expected<TlsContext, std::string> TlsContext::create(const std::filesystem::path& cert, const std::filesystem::path& key) {
        ERR_clear_error();
        SSL_CTX* raw = SSL_CTX_new(TLS_server_method());
        if (!raw) {
            return std::unexpected("cannot create a TLS context: " + openssl_errors());
        }
        TlsContext context(raw);

        // TLS 1.3 only: every 1.3 cipher suite is forward secret and authenticated
        if (SSL_CTX_set_min_proto_version(raw, TLS1_3_VERSION) != 1 || SSL_CTX_set_max_proto_version(raw, TLS1_3_VERSION) != 1) {
            return std::unexpected("cannot restrict TLS to version 1.3: " + openssl_errors());
        }
        // the server loop retries writes from a buffer that may have grown or moved in between
        SSL_CTX_set_mode(raw, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

        if (SSL_CTX_use_certificate_chain_file(raw, cert.string().c_str()) != 1) {
            return std::unexpected(std::format("tls_cert '{}': {}", cert.string(), openssl_errors()));
        }
        const auto mismatch = std::format("tls_key '{}' does not match tls_cert '{}'", key.string(), cert.string());
        if (SSL_CTX_use_PrivateKey_file(raw, key.string().c_str(), SSL_FILETYPE_PEM) != 1) {
            // OpenSSL notices a key from another certificate already while loading it
            if (ERR_GET_REASON(ERR_peek_last_error()) == X509_R_KEY_VALUES_MISMATCH) {
                ERR_clear_error();
                return std::unexpected(mismatch);
            }
            return std::unexpected(std::format("tls_key '{}': {}", key.string(), openssl_errors()));
        }
        if (SSL_CTX_check_private_key(raw) != 1) {
            return std::unexpected(mismatch);
        }
        SSL_CTX_set_alpn_select_cb(raw, select_alpn, nullptr);

        warn_if_key_is_readable(key);
        return context;
    }

} // namespace mw
