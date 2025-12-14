#pragma once

#include "apk_reader.hpp"
#include "signature_scheme.hpp"
#include <string>
#include <memory>
#include <vector>

namespace apksig {

/**
 * Verification result for an APK signature.
 */
struct VerificationResult {
    bool success;
    std::string error_message;
    std::vector<SignatureBlock> signature_blocks;  // v2 and/or v3
    std::vector<std::vector<std::uint8_t>> certificates;  // All certificates found
};

/**
 * Main API for APK signature verification.
 * 
 * This class orchestrates the verification process:
 * 1. Locate APK Signing Block
 * 2. Parse v2/v3 signature blocks
 * 3. Extract certificates
 * 4. Verify digests
 * 
 * Similar to ApkVerifier.java in the Java apksig library.
 */
class ApkVerifier {
public:
    /**
     * Verify APK signatures from a file path.
     * 
     * @param apk_path Path to the APK file
     * @return VerificationResult with success status and extracted information
     */
    static VerificationResult verify(const std::string& apk_path);
    
    /**
     * Verify APK signatures from a data source.
     * 
     * @param source Data source for the APK file
     * @return VerificationResult with success status and extracted information
     */
    static VerificationResult verify(const DataSource& source);
    
    /**
     * Get first certificate from APK as base64 string (like Java Signature class).
     * 
     * @param apk_path Path to the APK file
     * @return Base64-encoded certificate string, or empty string if not found
     */
    static std::string getCertificateBase64(const std::string& apk_path);
    
private:
    /**
     * Internal verification implementation.
     */
    static VerificationResult verifyInternal(const DataSource& source);
};

} // namespace apksig

