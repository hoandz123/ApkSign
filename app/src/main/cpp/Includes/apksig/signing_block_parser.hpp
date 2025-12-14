#pragma once

#include "apk_reader.hpp"
#include "signing_block.hpp"
#include <memory>
#include <vector>

namespace apksig {

/**
 * Parses the APK Signing Block and extracts signature scheme blocks.
 */
class SigningBlockParser {
public:
    /**
     * Parse the APK Signing Block and extract ID-value pairs.
     * 
     * @param source The APK file data source
     * @param location The location of the signing block
     * @return ApkSigningBlock if parsed successfully, nullptr otherwise
     */
    static std::unique_ptr<ApkSigningBlock> parse(const DataSource& source,
                                                  const SigningBlockLocation& location);
    
    /**
     * Extract v2 signature block from the signing block.
     * 
     * @param signing_block The parsed signing block
     * @return Raw v2 signature block data, or empty vector if not found
     */
    static std::vector<std::uint8_t> extractV2Block(const ApkSigningBlock& signing_block);
    
    /**
     * Extract v3 signature block from the signing block.
     * 
     * @param signing_block The parsed signing block
     * @return Raw v3 signature block data, or empty vector if not found
     */
    static std::vector<std::uint8_t> extractV3Block(const ApkSigningBlock& signing_block);
    
private:
    /**
     * Parse ID-value pairs from the signing block data.
     * Each pair is: [uint32 id][uint32 value_size][value_bytes]
     * 
     * @param data The signing block data (excluding size and magic)
     * @param pairs Output: parsed ID-value pairs
     * @return true if parsing succeeded
     */
    static bool parseIdValuePairs(const std::vector<std::uint8_t>& data,
                                 std::vector<IdValuePair>& pairs);
};

} // namespace apksig

