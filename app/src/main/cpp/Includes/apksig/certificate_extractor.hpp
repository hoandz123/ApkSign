#pragma once

#include "signature_scheme.hpp"
#include <vector>
#include <memory>
#include <openssl/x509.h>

namespace apksig {

/**
 * Extracts and parses X.509 certificates from signature blocks.
 */
class CertificateExtractor {
public:
    /**
     * Extract certificates from a signature block.
     * 
     * @param signature_block The parsed signature block
     * @return Vector of X.509 certificates (as DER-encoded bytes)
     */
    static std::vector<std::vector<std::uint8_t>> extractCertificates(
        const SignatureBlock& signature_block);
    
    /**
     * Parse an X.509 certificate from DER-encoded data.
     * 
     * @param der_data DER-encoded certificate
     * @return OpenSSL X509* pointer (caller must free with X509_free)
     */
    static X509* parseCertificate(const std::vector<std::uint8_t>& der_data);
    
    /**
     * Get certificate subject as a string.
     * 
     * @param cert OpenSSL X509 certificate
     * @return Subject DN string
     */
    static std::string getSubjectString(X509* cert);
    
    /**
     * Get certificate issuer as a string.
     * 
     * @param cert OpenSSL X509 certificate
     * @return Issuer DN string
     */
    static std::string getIssuerString(X509* cert);
    
    /**
     * Get certificate serial number as a string.
     * 
     * @param cert OpenSSL X509 certificate
     * @return Serial number as hex string
     */
    static std::string getSerialNumberString(X509* cert);
    
    /**
     * Encode certificate to base64 string (like Java Signature class).
     * 
     * @param der_data DER-encoded certificate
     * @return Base64-encoded certificate string
     */
    static std::string encodeCertificateBase64(const std::vector<std::uint8_t>& der_data);
};

} // namespace apksig

