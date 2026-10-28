#pragma once
#include <expected>
#include <filesystem>
#include <memory>
#include <string>

#include <openssl/ssl.h>

namespace mw {

    // the server side TLS settings: TLS 1.3 only, the certificate chain and private key, and ALPN "dot"
    // when the client offers it (not required)
    class TlsContext {
    public:
        static std::expected<TlsContext, std::string> create(const std::filesystem::path& cert, const std::filesystem::path& key);

        SSL_CTX* get() const noexcept { return ctx_.get(); }

    private:
        struct Free {
            void operator()(SSL_CTX* ctx) const noexcept { SSL_CTX_free(ctx); }
        };

        explicit TlsContext(SSL_CTX* ctx) : ctx_(ctx) {}

        std::unique_ptr<SSL_CTX, Free> ctx_;
    };

    // everything in OpenSSL's error queue as one line; reading empties the queue
    std::string openssl_errors();

} // namespace mw
