#include "apksig/apk_verifier.hpp"
#include "apksig/apk_reader.hpp"
#include "apksig/signing_block_locator.hpp"
#include "apksig/signing_block_parser.hpp"
#include "apksig/v2_v3_parser.hpp"
#include "apksig/certificate_extractor.hpp"
#include "apksig/digest_verifier.hpp"
#include <memory>
#include <android/log.h>

#define LOG_TAG "Loader"
#define LOGI_VERIFIER(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE_VERIFIER(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace apksig {

VerificationResult ApkVerifier::verify(const std::string& apk_path) {
    try {
        FileDataSource source(apk_path);
        return verify(source);
    } catch (const std::exception& e) {
        VerificationResult result;
        result.success = false;
        result.error_message = std::string("Failed to open APK: ") + e.what();
        return result;
    }
}

VerificationResult ApkVerifier::verify(const DataSource& source) {
    return verifyInternal(source);
}

VerificationResult ApkVerifier::verifyInternal(const DataSource& source) {
    VerificationResult result;
    
    // Step 1: Locate APK Signing Block
    auto location = SigningBlockLocator::locate(source);
    if (!location) {
        result.success = false;
        result.error_message = "APK Signing Block not found";
        return result;
    }
    
    // Step 2: Parse the Signing Block
    auto signing_block = SigningBlockParser::parse(source, *location);
    if (!signing_block) {
        result.success = false;
        result.error_message = "Failed to parse APK Signing Block";
        return result;
    }
    
    // Step 3: Extract v2 and v3 signature blocks
    std::vector<std::uint8_t> v2_block = SigningBlockParser::extractV2Block(*signing_block);
    std::vector<std::uint8_t> v3_block = SigningBlockParser::extractV3Block(*signing_block);
    
    if (v2_block.empty() && v3_block.empty()) {
        result.success = false;
        result.error_message = "No v2 or v3 signature blocks found";
        return result;
    }
    
    if (!v2_block.empty()) {
        auto v2_signature = V2V3Parser::parseV2(v2_block);
        if (v2_signature) {
            result.signature_blocks.push_back(*v2_signature);
            auto certs = CertificateExtractor::extractCertificates(*v2_signature);
            result.certificates.insert(result.certificates.end(), certs.begin(), certs.end());
        }
    }
    
    if (!v3_block.empty()) {
        auto v3_signature = V2V3Parser::parseV3(v3_block);
        if (v3_signature) {
            result.signature_blocks.push_back(*v3_signature);
            auto certs = CertificateExtractor::extractCertificates(*v3_signature);
            result.certificates.insert(result.certificates.end(), certs.begin(), certs.end());
        }
    }
    
    ContentDigests computed_digests = DigestVerifier::computeDigests(source, *location);
    
    result.success = !result.signature_blocks.empty() && !result.certificates.empty();
    
    if (!result.success) {
        result.error_message = "Failed to extract signatures or certificates";
    }
    
    return result;
}

std::string ApkVerifier::getCertificateBase64(const std::string& apk_path) {
    try {
        VerificationResult result = verify(apk_path);
        if (result.success && !result.certificates.empty()) {
            return CertificateExtractor::encodeCertificateBase64(result.certificates[0]);
        }
    } catch (...) {
        // Return empty string on error
    }
    return "";
}

} // namespace apksig

