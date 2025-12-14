#pragma once

#include "apk_reader.hpp"
#include "signing_block.hpp"
#include "signature_scheme.hpp"
#include <vector>
#include <memory>

namespace apksig {

/**
 * Computes and verifies APK content digests.
 * 
 * The digest is computed over the APK contents, excluding the APK Signing Block.
 * This matches the behavior of Google's apksig library.
 */
class DigestVerifier {
public:
    /**
     * Compute content digests for the APK.
     * 
     * The digest covers:
     * 1. All bytes before the APK Signing Block
     * 2. All bytes after the APK Signing Block (Central Directory + EOCD)
     * 
     * @param source The APK file data source
     * @param signing_block_location Location of the signing block to exclude
     * @return ContentDigests with SHA-256 and SHA-512 digests
     */
    static ContentDigests computeDigests(const DataSource& source,
                                        const SigningBlockLocation& signing_block_location);
    
    /**
     * Verify that computed digests match those in the signature block.
     * 
     * @param computed_digests Digests computed from APK content
     * @param signature_block The parsed signature block containing expected digests
     * @return true if digests match
     */
    static bool verifyDigests(const ContentDigests& computed_digests,
                             const SignatureBlock& signature_block);
    
private:
    /**
     * Compute SHA-256 digest of APK content (excluding signing block).
     */
    static std::vector<std::uint8_t> computeSha256(const DataSource& source,
                                                   const SigningBlockLocation& location);
    
    /**
     * Compute SHA-512 digest of APK content (excluding signing block).
     */
    static std::vector<std::uint8_t> computeSha512(const DataSource& source,
                                                   const SigningBlockLocation& location);
    
    /**
     * Extract content digests from signed data in signature block.
     */
    static ContentDigests extractDigestsFromSignedData(const SignatureBlock& signature_block);
};

} // namespace apksig

