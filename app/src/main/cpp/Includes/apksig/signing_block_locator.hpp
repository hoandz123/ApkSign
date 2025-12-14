#pragma once

#include "apk_reader.hpp"
#include "signing_block.hpp"
#include <memory>

namespace apksig {

/**
 * Locates the APK Signing Block in an APK file.
 * 
 * The APK Signing Block is located immediately before the ZIP Central Directory.
 * This class finds the End of Central Directory (EOCD) record, then locates
 * the signing block that precedes it.
 */
class SigningBlockLocator {
public:
    /**
     * Locate the APK Signing Block in the given data source.
     * 
     * @param source The APK file data source
     * @return SigningBlockLocation if found, nullptr otherwise
     */
    static std::unique_ptr<SigningBlockLocation> locate(const DataSource& source);
    
private:
    /**
     * Find the End of Central Directory (EOCD) record.
     * EOCD is located at the end of the file and has signature 0x06054b50.
     * 
     * @param source The APK file data source
     * @param eocd_offset Output: offset of EOCD record
     * @return true if EOCD found, false otherwise
     */
    static bool findEocd(const DataSource& source, std::uint64_t& eocd_offset);
    
    /**
     * Read EOCD record and extract Central Directory offset.
     * 
     * @param source The APK file data source
     * @param eocd_offset Offset of EOCD record
     * @param central_dir_offset Output: offset of Central Directory
     * @return true if EOCD parsed successfully
     */
    static bool parseEocd(const DataSource& source, std::uint64_t eocd_offset,
                         std::uint64_t& central_dir_offset);
    
    /**
     * Verify that the signing block has correct structure.
     * 
     * @param source The APK file data source
     * @param location The signing block location to verify
     * @return true if structure is valid
     */
    static bool verifySigningBlockStructure(const DataSource& source,
                                           const SigningBlockLocation& location);
};

} // namespace apksig

