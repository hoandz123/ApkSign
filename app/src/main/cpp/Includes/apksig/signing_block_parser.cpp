#include "apksig/signing_block_parser.hpp"
#include "apksig/signing_block.hpp"
#include <stdexcept>
#include <algorithm>
#include <android/log.h>

#define LOG_TAG "Loader"
#define LOGI_PARSER(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE_PARSER(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace apksig {

std::unique_ptr<ApkSigningBlock> SigningBlockParser::parse(const DataSource& source,
                                                           const SigningBlockLocation& location) {
    LOGI_PARSER("Parsing signing block at offset %llu, size %llu",
                static_cast<unsigned long long>(location.offset),
                static_cast<unsigned long long>(location.size));
    
    std::uint64_t total_size = location.size + 8;
    std::uint64_t pairs_size = total_size - 24 - 8;
    
    if (pairs_size > location.size || pairs_size < 0) {
        LOGE_PARSER("Invalid pairs size: %llu (block size: %llu, total size: %llu)",
                    static_cast<unsigned long long>(pairs_size),
                    static_cast<unsigned long long>(location.size),
                    static_cast<unsigned long long>(total_size));
        return nullptr;
    }
    
    std::vector<std::uint8_t> pairs_data(pairs_size);
    std::size_t bytes_read = source.read(location.offset + 8, pairs_size, pairs_data.data());
    
    if (bytes_read != pairs_size) {
        LOGE_PARSER("Failed to read pairs data: read %zu bytes, expected %llu",
                    bytes_read, static_cast<unsigned long long>(pairs_size));
        return nullptr;
    }
    
    LOGI_PARSER("Read %zu bytes of pairs data", bytes_read);
    
    auto signing_block = std::make_unique<ApkSigningBlock>();
    signing_block->size = location.size;
    
    if (!parseIdValuePairs(pairs_data, signing_block->pairs)) {
        LOGE_PARSER("Failed to parse ID-value pairs");
        return nullptr;
    }
    
    LOGI_PARSER("Parsed %zu ID-value pairs", signing_block->pairs.size());
    
    std::uint64_t footer_offset = location.offset + total_size - 24;
    signing_block->size_again = source.readUint64(footer_offset);
    signing_block->magic_lo = source.readUint64(footer_offset + 8);
    signing_block->magic_hi = source.readUint64(footer_offset + 16);
    
    LOGI_PARSER("Footer: size_again=%llu, magic_lo=0x%016llx, magic_hi=0x%016llx",
                static_cast<unsigned long long>(signing_block->size_again),
                static_cast<unsigned long long>(signing_block->magic_lo),
                static_cast<unsigned long long>(signing_block->magic_hi));
    
    if (signing_block->size_again != signing_block->size) {
        LOGE_PARSER("Size mismatch: size=%llu, size_again=%llu",
                    static_cast<unsigned long long>(signing_block->size),
                    static_cast<unsigned long long>(signing_block->size_again));
        return nullptr;
    }
    
    if (signing_block->magic_lo != APK_SIGNING_BLOCK_MAGIC_LO ||
        signing_block->magic_hi != APK_SIGNING_BLOCK_MAGIC_HI) {
        LOGE_PARSER("Magic mismatch: LO=0x%016llx (expected 0x%016llx), HI=0x%016llx (expected 0x%016llx)",
                    static_cast<unsigned long long>(signing_block->magic_lo),
                    static_cast<unsigned long long>(APK_SIGNING_BLOCK_MAGIC_LO),
                    static_cast<unsigned long long>(signing_block->magic_hi),
                    static_cast<unsigned long long>(APK_SIGNING_BLOCK_MAGIC_HI));
        return nullptr;
    }
    
    LOGI_PARSER("Signing block parsed successfully");
    return signing_block;
}

std::vector<std::uint8_t> SigningBlockParser::extractV2Block(const ApkSigningBlock& signing_block) {
    for (const auto& pair : signing_block.pairs) {
        if (pair.id == APK_SIGNATURE_SCHEME_V2_ID) {
            return pair.value;
        }
    }
    return {};
}

std::vector<std::uint8_t> SigningBlockParser::extractV3Block(const ApkSigningBlock& signing_block) {
    for (const auto& pair : signing_block.pairs) {
        if (pair.id == APK_SIGNATURE_SCHEME_V3_ID) {
            return pair.value;
        }
    }
    return {};
}

bool SigningBlockParser::parseIdValuePairs(const std::vector<std::uint8_t>& data,
                                          std::vector<IdValuePair>& pairs) {
    std::size_t offset = 0;
    int pair_count = 0;
    
    while (offset < data.size()) {
        if (offset + 8 > data.size()) {
            if (offset < data.size()) {
                LOGE_PARSER("Not enough data for pair %d at offset %zu (need 8 bytes for length, have %zu)",
                            pair_count, offset, data.size() - offset);
            }
            break;
        }
        
        std::uint64_t pair_length = static_cast<std::uint64_t>(data[offset]) |
                                    (static_cast<std::uint64_t>(data[offset + 1]) << 8) |
                                    (static_cast<std::uint64_t>(data[offset + 2]) << 16) |
                                    (static_cast<std::uint64_t>(data[offset + 3]) << 24) |
                                    (static_cast<std::uint64_t>(data[offset + 4]) << 32) |
                                    (static_cast<std::uint64_t>(data[offset + 5]) << 40) |
                                    (static_cast<std::uint64_t>(data[offset + 6]) << 48) |
                                    (static_cast<std::uint64_t>(data[offset + 7]) << 56);
        offset += 8;
        
        if (pair_length < 4 || pair_length > static_cast<std::uint64_t>(INT_MAX)) {
            LOGE_PARSER("Pair %d length out of range: %llu", pair_count, static_cast<unsigned long long>(pair_length));
            return false;
        }
        
        if (pair_length > data.size() - offset) {
            LOGE_PARSER("Pair %d length %llu exceeds remaining data %zu at offset %zu",
                        pair_count, static_cast<unsigned long long>(pair_length), data.size() - offset, offset);
            return false;
        }
        
        if (offset + 4 > data.size()) {
            LOGE_PARSER("Not enough data for pair %d ID at offset %zu", pair_count, offset);
            return false;
        }
        
        IdValuePair pair;
        pair.id = static_cast<std::uint32_t>(data[offset]) |
                  (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                  (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
                  (static_cast<std::uint32_t>(data[offset + 3]) << 24);
        offset += 4;
        
        std::uint32_t value_size = static_cast<std::uint32_t>(pair_length) - 4;
        
        if (value_size > data.size() - offset) {
            LOGE_PARSER("Value size %u exceeds remaining data %zu at offset %zu",
                        value_size, data.size() - offset, offset);
            return false;
        }
        
        pair.value.resize(value_size);
        std::copy(data.begin() + offset, data.begin() + offset + value_size, pair.value.begin());
        offset += value_size;
        
        pairs.push_back(std::move(pair));
        pair_count++;
    }
    
    LOGI_PARSER("Successfully parsed %d ID-value pairs", pair_count);
    return true;
}

} // namespace apksig

