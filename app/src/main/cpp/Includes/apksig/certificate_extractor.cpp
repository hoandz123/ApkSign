#include "apksig/certificate_extractor.hpp"
#include "apksig/signature_scheme.hpp"
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>

namespace apksig {

std::vector<std::vector<std::uint8_t>> CertificateExtractor::extractCertificates(
    const SignatureBlock& signature_block) {
    std::vector<std::vector<std::uint8_t>> all_certificates;
    
    for (const auto& signer : signature_block.signers) {
        for (const auto& cert : signer.certificates) {
            all_certificates.push_back(cert);
        }
    }
    
    return all_certificates;
}

X509* CertificateExtractor::parseCertificate(const std::vector<std::uint8_t>& der_data) {
    const unsigned char* data = der_data.data();
    X509* cert = d2i_X509(nullptr, &data, static_cast<long>(der_data.size()));
    return cert;
}

std::string CertificateExtractor::getSubjectString(X509* cert) {
    if (!cert) {
        return "";
    }
    
    X509_NAME* subject = X509_get_subject_name(cert);
    if (!subject) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }
    
    X509_NAME_print_ex(bio, subject, 0, XN_FLAG_RFC2253);
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    
    BIO_free(bio);
    return result;
}

std::string CertificateExtractor::getIssuerString(X509* cert) {
    if (!cert) {
        return "";
    }
    
    X509_NAME* issuer = X509_get_issuer_name(cert);
    if (!issuer) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return "";
    }
    
    X509_NAME_print_ex(bio, issuer, 0, XN_FLAG_RFC2253);
    
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    
    BIO_free(bio);
    return result;
}

std::string CertificateExtractor::getSerialNumberString(X509* cert) {
    if (!cert) {
        return "";
    }
    
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial) {
        return "";
    }
    
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    if (!bn) {
        return "";
    }
    
    char* hex = BN_bn2hex(bn);
    if (!hex) {
        BN_free(bn);
        return "";
    }
    
    std::string result(hex);
    OPENSSL_free(hex);
    BN_free(bn);
    
    return result;
}

std::string CertificateExtractor::encodeCertificateBase64(const std::vector<std::uint8_t>& der_data) {
    if (der_data.empty()) {
        return "";
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    
    BIO_write(bio, der_data.data(), static_cast<int>(der_data.size()));
    BIO_flush(bio);
    
    char* encoded_data = nullptr;
    long encoded_len = BIO_get_mem_data(bio, &encoded_data);
    
    std::string result(encoded_data, encoded_len);
    
    BIO_free_all(bio);
    
    return result;
}

} // namespace apksig

