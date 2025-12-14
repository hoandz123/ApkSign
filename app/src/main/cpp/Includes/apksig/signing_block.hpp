#pragma once

#include <cstdint>
#include <vector>
#include <memory>

namespace apksig {

/**
 * APK Signing Block magic constant.
 * "APK Sig Block 42" in ASCII - 16 bytes total
 * Magic is split into 2 uint64 (little-endian):
 * - LO (first 8 bytes): "APK Sig " = 0x20676953204b5041ULL
 * - HI (last 8 bytes): "Block 42" = 0x3234206b636f6c42ULL
 */
constexpr std::uint64_t APK_SIGNING_BLOCK_MAGIC_LO = 0x20676953204b5041ULL;
constexpr std::uint64_t APK_SIGNING_BLOCK_MAGIC_HI = 0x3234206b636f6c42ULL;

/**
 * APK Signature Scheme v2 ID
 */
constexpr std::uint32_t APK_SIGNATURE_SCHEME_V2_ID = 0x7109871a;

/**
 * APK Signature Scheme v3 ID
 */
constexpr std::uint32_t APK_SIGNATURE_SCHEME_V3_ID = 0xf05368c0;

/**
 * Represents an ID-value pair in the APK Signing Block.
 */
struct IdValuePair {
    std::uint32_t id;
    std::vector<std::uint8_t> value;
};

/**
 * Represents the APK Signing Block structure.
 * Format: [uint64 size][pairs...][uint64 size][magic]
 */
struct ApkSigningBlock {
    std::uint64_t size;
    std::vector<IdValuePair> pairs;
    std::uint64_t size_again;  // Must match 'size'
    std::uint64_t magic_lo;    // Must be APK_SIGNING_BLOCK_MAGIC_LO
    std::uint64_t magic_hi;    // Must be APK_SIGNING_BLOCK_MAGIC_HI
};

/**
 * Location of the APK Signing Block in the APK file.
 */
struct SigningBlockLocation {
    std::uint64_t offset;      // Offset of the signing block in the APK
    std::uint64_t size;         // Size of the signing block (excluding magic)
    std::uint64_t central_dir_offset;  // Offset of ZIP Central Directory
};

} // namespace apksig

