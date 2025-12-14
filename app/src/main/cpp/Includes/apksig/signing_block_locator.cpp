#include "apksig/signing_block_locator.hpp"
#include "apksig/signing_block.hpp"
#include <stdexcept>
#include <algorithm>
#include <cstdio>
#include <android/log.h>

#define LOG_TAG "Loader"
#define LOGI_LOCATOR(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE_LOCATOR(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace apksig {

namespace {
    // ZIP End of Central Directory signature
    constexpr std::uint32_t EOCD_SIGNATURE = 0x06054b50;
    
    // Maximum EOCD comment length (65535 bytes)
    constexpr std::uint64_t MAX_EOCD_COMMENT_LENGTH = 65535;
    
    // Minimum EOCD size (22 bytes)
    constexpr std::uint64_t MIN_EOCD_SIZE = 22;
    
    // Maximum search distance from end of file for EOCD
    constexpr std::uint64_t MAX_EOCD_SEARCH_DISTANCE = MIN_EOCD_SIZE + MAX_EOCD_COMMENT_LENGTH;
}

std::unique_ptr<SigningBlockLocation> SigningBlockLocator::locate(const DataSource& source) {
    std::uint64_t eocd_offset;
    if (!findEocd(source, eocd_offset)) {
        LOGE_LOCATOR("Failed to find EOCD");
        return nullptr;
    }
    
    std::uint64_t central_dir_offset;
    if (!parseEocd(source, eocd_offset, central_dir_offset)) {
        LOGE_LOCATOR("Failed to parse EOCD");
        return nullptr;
    }
    
    if (central_dir_offset < 24) {
        LOGE_LOCATOR("Central dir offset too small: %llu", static_cast<unsigned long long>(central_dir_offset));
        return nullptr;
    }
    
    std::uint64_t footer_offset = central_dir_offset - 24;
    std::uint8_t footer[24];
    if (source.read(footer_offset, 24, footer) != 24) {
        LOGE_LOCATOR("Failed to read footer");
        return nullptr;
    }
    
    std::uint64_t magic_lo = source.readUint64(footer_offset + 8);
    std::uint64_t magic_hi = source.readUint64(footer_offset + 16);
    
    if (magic_lo != APK_SIGNING_BLOCK_MAGIC_LO || magic_hi != APK_SIGNING_BLOCK_MAGIC_HI) {
        LOGE_LOCATOR("Magic mismatch: LO=0x%016llx (expected 0x%016llx), HI=0x%016llx (expected 0x%016llx)",
                     static_cast<unsigned long long>(magic_lo),
                     static_cast<unsigned long long>(APK_SIGNING_BLOCK_MAGIC_LO),
                     static_cast<unsigned long long>(magic_hi),
                     static_cast<unsigned long long>(APK_SIGNING_BLOCK_MAGIC_HI));
        return nullptr;
    }
    
    std::uint64_t apk_sig_block_size_in_footer = source.readUint64(footer_offset);
    LOGI_LOCATOR("Block size in footer: %llu", static_cast<unsigned long long>(apk_sig_block_size_in_footer));
    
    if (apk_sig_block_size_in_footer < 24) {
        LOGE_LOCATOR("Block size too small: %llu (minimum 24)", static_cast<unsigned long long>(apk_sig_block_size_in_footer));
        return nullptr;
    }
    if (apk_sig_block_size_in_footer > static_cast<std::uint64_t>(INT_MAX) - 8) {
        LOGE_LOCATOR("Block size too large: %llu (maximum %d)", 
                     static_cast<unsigned long long>(apk_sig_block_size_in_footer), INT_MAX - 8);
        return nullptr;
    }
    
    std::uint64_t total_size = apk_sig_block_size_in_footer + 8;
    if (central_dir_offset < total_size) {
        LOGE_LOCATOR("Central dir offset too small for total size: %llu < %llu",
                     static_cast<unsigned long long>(central_dir_offset),
                     static_cast<unsigned long long>(total_size));
        return nullptr;
    }
    
    std::uint64_t signing_block_offset = central_dir_offset - total_size;
    LOGI_LOCATOR("Signing block offset: %llu", static_cast<unsigned long long>(signing_block_offset));
    
    if (signing_block_offset < 0 || signing_block_offset >= central_dir_offset) {
        LOGE_LOCATOR("Signing block offset out of range: %llu", static_cast<unsigned long long>(signing_block_offset));
        return nullptr;
    }
    
    std::uint64_t apk_sig_block_size_in_header = source.readUint64(signing_block_offset);
    LOGI_LOCATOR("Block size in header: %llu", static_cast<unsigned long long>(apk_sig_block_size_in_header));
    
    if (apk_sig_block_size_in_header != apk_sig_block_size_in_footer) {
        LOGE_LOCATOR("Size mismatch: header=%llu, footer=%llu",
                     static_cast<unsigned long long>(apk_sig_block_size_in_header),
                     static_cast<unsigned long long>(apk_sig_block_size_in_footer));
        return nullptr;
    }
    
    LOGI_LOCATOR("APK Signing Block located successfully at offset %llu, size %llu",
                 static_cast<unsigned long long>(signing_block_offset),
                 static_cast<unsigned long long>(apk_sig_block_size_in_footer));
    
    auto location = std::make_unique<SigningBlockLocation>();
    location->offset = signing_block_offset;
    location->size = apk_sig_block_size_in_footer;
    location->central_dir_offset = central_dir_offset;
    
    return location;
}

bool SigningBlockLocator::findEocd(const DataSource& source, std::uint64_t& eocd_offset) {
    std::uint64_t file_size = source.size();
    
    if (file_size < MIN_EOCD_SIZE) {
        return false;
    }
    
    // Search backwards from end of file for EOCD signature
    std::uint64_t search_start = (file_size < MAX_EOCD_SEARCH_DISTANCE) 
                                 ? 0 
                                 : file_size - MAX_EOCD_SEARCH_DISTANCE;
    
    // Start from end and search backwards
    std::uint64_t start_offset = (file_size >= MIN_EOCD_SIZE) 
                                 ? file_size - MIN_EOCD_SIZE 
                                 : 0;
    
    for (std::uint64_t offset = start_offset; offset >= search_start; --offset) {
        if (offset + 4 > file_size) {
            continue;  // Not enough bytes remaining
        }
        
        std::uint32_t signature = source.readUint32(offset);
        if (signature == EOCD_SIGNATURE) {
            eocd_offset = offset;
            return true;
        }
    }
    
    return false;
}

bool SigningBlockLocator::parseEocd(const DataSource& source, std::uint64_t eocd_offset,
                                   std::uint64_t& central_dir_offset) {
    // EOCD structure (little-endian):
    // uint32 signature (0x06054b50)
    // uint16 disk_number
    // uint16 central_dir_disk
    // uint16 num_entries_this_disk
    // uint16 total_entries
    // uint32 central_dir_size
    // uint32 central_dir_offset  <- we need this
    // uint16 comment_length
    
    if (source.size() < eocd_offset + 22) {
        return false;
    }
    
    // Read central_dir_offset (at offset 16 from EOCD start)
    central_dir_offset = source.readUint32(eocd_offset + 16);
    
    // Validate that central_dir_offset is reasonable
    if (central_dir_offset >= source.size()) {
        return false;
    }
    
    return true;
}

bool SigningBlockLocator::verifySigningBlockStructure(const DataSource& source,
                                                      const SigningBlockLocation& location) {
    std::uint64_t size_at_start = source.readUint64(location.offset);
    if (size_at_start != location.size) {
        return false;
    }
    
    std::uint64_t footer_offset = location.offset + location.size + 8;
    std::uint64_t size_at_end = source.readUint64(footer_offset);
    if (size_at_end != location.size) {
        return false;
    }
    
    std::uint64_t magic_lo = source.readUint64(footer_offset + 8);
    std::uint64_t magic_hi = source.readUint64(footer_offset + 16);
    if (magic_lo != APK_SIGNING_BLOCK_MAGIC_LO || magic_hi != APK_SIGNING_BLOCK_MAGIC_HI) {
        return false;
    }
    
    return true;
}

} // namespace apksig

