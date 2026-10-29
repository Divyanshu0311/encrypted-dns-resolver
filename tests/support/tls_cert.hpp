#pragma once

// A throwaway P-256 key and self-signed "localhost" certificate, written as PEM files into a test's
// TempDir, so no key material ever lives in the repo. TestCa is a throwaway certificate authority for the
// DNS-over-TLS upstream tests: it issues certificates with the names, addresses and lifetimes a test needs.

#include "support/temp_dir.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace mw::test {

    struct TestCert {
        std::string cert; // file paths
        std::string key;
    };

    inline TestCert make_test_cert(const support::TempDir& dir, const std::string& prefix = "server") {
        EVP_PKEY* pkey = EVP_EC_gen("P-256");
        X509* x509     = X509_new();
        if (!pkey || !x509) {
            throw std::runtime_error("make_test_cert: OpenSSL allocation failed");
        }
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_getm_notBefore(x509), 0);
        X509_gmtime_adj(X509_getm_notAfter(x509), 3600);
        X509_set_pubkey(x509, pkey);
        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
        X509_set_issuer_name(x509, name);
        X509_sign(x509, pkey, EVP_sha256());

        TestCert out{ (dir.path() / (prefix + ".pem")).string(), (dir.path() / (prefix + ".key")).string() };
        BIO* cert_bio = BIO_new_file(out.cert.c_str(), "w");
        BIO* key_bio  = BIO_new_file(out.key.c_str(), "w");
        const bool ok = cert_bio && key_bio && PEM_write_bio_X509(cert_bio, x509) == 1 &&
                        PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
        BIO_free(cert_bio);
        BIO_free(key_bio);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        if (!ok) {
            throw std::runtime_error("make_test_cert: could not write the PEM files");
        }
        std::filesystem::permissions(out.key, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        return out;
    }

    namespace detail {
        struct FreeKey {
            void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
        };
        struct FreeCert {
            void operator()(X509* x) const { X509_free(x); }
        };
        using Key  = std::unique_ptr<EVP_PKEY, FreeKey>;
        using Cert = std::unique_ptr<X509, FreeCert>;

        inline void add_extension(X509* cert, X509* issuer, int nid, const std::string& value) {
            X509V3_CTX ctx;
            X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
            X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value.c_str());
            if (!ext) {
                throw std::runtime_error("TestCa: bad extension " + value);
            }
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }

        // a v3 certificate for key, valid from now + from_s for for_s seconds, not yet signed
        inline Cert new_cert(EVP_PKEY* key, const std::string& cn, long serial, long from_s, long for_s) {
            Cert cert(X509_new());
            X509_set_version(cert.get(), 2);
            ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
            X509_gmtime_adj(X509_getm_notBefore(cert.get()), from_s);
            X509_gmtime_adj(X509_getm_notAfter(cert.get()), from_s + for_s);
            X509_set_pubkey(cert.get(), key);
            X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1,
                                       -1, 0);
            return cert;
        }

        inline void write_pem(const std::string& cert_path, X509* cert, const std::string& key_path, EVP_PKEY* key) {
            BIO* cert_bio = BIO_new_file(cert_path.c_str(), "w");
            const bool cert_ok = cert_bio && PEM_write_bio_X509(cert_bio, cert) == 1;
            BIO_free(cert_bio);
            bool key_ok = true;
            if (!key_path.empty()) {
                BIO* key_bio = BIO_new_file(key_path.c_str(), "w");
                key_ok       = key_bio && PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
                BIO_free(key_bio);
            }
            if (!cert_ok || !key_ok) {
                throw std::runtime_error("TestCa: could not write the PEM files");
            }
        }
    } // namespace detail

    struct LeafOptions {
        std::string common_name = "dns.test";
        std::vector<std::string> dns_names{ "dns.test" }; // subjectAltName DNS entries
        std::vector<std::string> ips{ "127.0.0.1" };      // subjectAltName IP entries
        long valid_from_s = -60;                          // relative to now
        long valid_for_s  = 3600;
    };

    class TestCa {
    public:
        // writes <prefix>.pem (the CA certificate, what a client trusts) into dir
        TestCa(const support::TempDir& dir, const std::string& name = "Test CA", const std::string& prefix = "ca")
            : dir_(dir), key_(EVP_EC_gen("P-256")) {
            cert_ = detail::new_cert(key_.get(), name, 1, -60, 3600);
            X509_set_issuer_name(cert_.get(), X509_get_subject_name(cert_.get()));
            detail::add_extension(cert_.get(), cert_.get(), NID_basic_constraints, "critical,CA:TRUE");
            detail::add_extension(cert_.get(), cert_.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
            detail::add_extension(cert_.get(), cert_.get(), NID_subject_key_identifier, "hash");
            X509_sign(cert_.get(), key_.get(), EVP_sha256());
            cert_file_ = (dir.path() / (prefix + ".pem")).string();
            detail::write_pem(cert_file_, cert_.get(), "", nullptr);
        }

        const std::string& cert_file() const { return cert_file_; }

        // a server certificate and key signed by this CA, as <prefix>.pem and <prefix>.key
        TestCert issue(const std::string& prefix, const LeafOptions& opts = {}) {
            detail::Key key(EVP_EC_gen("P-256"));
            auto cert = detail::new_cert(key.get(), opts.common_name, ++serial_, opts.valid_from_s, opts.valid_for_s);
            X509_set_issuer_name(cert.get(), X509_get_subject_name(cert_.get()));
            detail::add_extension(cert.get(), cert_.get(), NID_basic_constraints, "critical,CA:FALSE");
            detail::add_extension(cert.get(), cert_.get(), NID_ext_key_usage, "serverAuth");
            detail::add_extension(cert.get(), cert_.get(), NID_authority_key_identifier, "keyid:always");
            std::string san;
            for (const auto& d : opts.dns_names) {
                san += (san.empty() ? "DNS:" : ",DNS:") + d;
            }
            for (const auto& ip : opts.ips) {
                san += (san.empty() ? "IP:" : ",IP:") + ip;
            }
            if (!san.empty()) {
                detail::add_extension(cert.get(), cert_.get(), NID_subject_alt_name, san);
            }
            X509_sign(cert.get(), key_.get(), EVP_sha256());

            TestCert out{ (dir_.path() / (prefix + ".pem")).string(), (dir_.path() / (prefix + ".key")).string() };
            detail::write_pem(out.cert, cert.get(), out.key, key.get());
            std::filesystem::permissions(out.key, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            return out;
        }

    private:
        const support::TempDir& dir_;
        detail::Key key_;
        detail::Cert cert_;
        std::string cert_file_;
        long serial_ = 1;
    };

} // namespace mw::test
