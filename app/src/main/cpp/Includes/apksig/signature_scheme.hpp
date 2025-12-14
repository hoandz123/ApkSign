#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

namespace apksig {

/**
 * Signature algorithm identifiers (from SignatureAlgorithm.java).
 */
enum class SignatureAlgorithm : std::uint32_t {
    RSA_PSS_WITH_SHA256 = 0x0101,
    RSA_PSS_WITH_SHA512 = 0x0102,
    RSA_PKCS1_V1_5_WITH_SHA256 = 0x0103,
    RSA_PKCS1_V1_5_WITH_SHA512 = 0x0104,
    ECDSA_WITH_SHA256 = 0x0201,
    ECDSA_WITH_SHA512 = 0x0202,
    DSA_WITH_SHA256 = 0x0301,
    DSA_WITH_SHA512 = 0x0302,
};

/**
 * Digest algorithm identifiers.
 */
enum class DigestAlgorithm : std::uint32_t {
    SHA256 = 0x0101,
    SHA512 = 0x0102,
};

/**
 * Represents a signer in v2/v3 signature scheme.
 */
struct Signer {
    std::vector<std::uint8_t> signed_data;
    std::vector<std::vector<std::uint8_t>> signatures;  // One per algorithm
    std::vector<std::uint32_t> signature_algorithms;
    std::vector<std::vector<std::uint8_t>> certificates;  // X.509 certificates (DER)
    std::uint32_t min_sdk_version;  // v3 only
    std::uint32_t max_sdk_version;  // v3 only
};

/**
 * Represents a v2 or v3 signature block.
 */
struct SignatureBlock {
    std::uint32_t scheme_id;  // APK_SIGNATURE_SCHEME_V2_ID or V3_ID
    std::vector<Signer> signers;
};

/**
 * Parsed content digests from signed data.
 */
struct ContentDigests {
    std::vector<std::uint8_t> sha256;
    std::vector<std::uint8_t> sha512;
};

} // namespace apksig

