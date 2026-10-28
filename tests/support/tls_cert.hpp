#pragma once

// A throwaway P-256 key and self-signed "localhost" certificate, written as PEM files into a test's
// TempDir, so no key material ever lives in the repo.

#include "support/temp_dir.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <filesystem>
#include <stdexcept>
#include <string>

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

} // namespace mw::test
