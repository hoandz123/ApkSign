#pragma once

#include "signature_scheme.hpp"
#include <vector>
#include <memory>

namespace apksig {

/**
 * Parser for APK Signature Scheme v2 and v3 blocks.
 * 
 * Both v2 and v3 use similar structures:
 * - SignedData (ASN.1)
 * - Signers (one or more)
 * - Certificates (X.509, DER-encoded)
 * - Signatures (one per algorithm)
 */
class V2V3Parser {
public:
    /**
     * Parse a v2 signature block.
     * 
     * @param block_data Raw v2 signature block data
     * @return Parsed SignatureBlock, or nullptr on error
     */
    static std::unique_ptr<SignatureBlock> parseV2(const std::vector<std::uint8_t>& block_data);
    
    /**
     * Parse a v3 signature block.
     * 
     * @param block_data Raw v3 signature block data
     * @return Parsed SignatureBlock, or nullptr on error
     */
    static std::unique_ptr<SignatureBlock> parseV3(const std::vector<std::uint8_t>& block_data);
    
private:
    /**
     * Parse a signature block (common logic for v2 and v3).
     * 
     * @param block_data Raw signature block data
     * @param scheme_id Expected scheme ID (V2 or V3)
     * @return Parsed SignatureBlock, or nullptr on error
     */
    static std::unique_ptr<SignatureBlock> parse(const std::vector<std::uint8_t>& block_data,
                                                 std::uint32_t scheme_id);
    
    /**
     * Parse SignedData structure (ASN.1).
     * 
     * @param signed_data_bytes DER-encoded SignedData
     * @param signers Output: parsed signers
     * @return true if parsing succeeded
     */
    static bool parseSignedData(const std::vector<std::uint8_t>& signed_data_bytes,
                               std::vector<Signer>& signers);
    
    /**
     * Parse a SignerInfo structure from ASN.1.
     * 
     * @param signer_info_bytes DER-encoded SignerInfo
     * @param signer Output: parsed signer
     * @return true if parsing succeeded
     */
    static bool parseSignerInfo(const std::vector<std::uint8_t>& signer_info_bytes,
                               Signer& signer);
    
    /**
     * Extract certificates from SignerInfo.
     * 
     * @param signer_info_bytes DER-encoded SignerInfo
     * @param certificates Output: extracted certificates (DER-encoded)
     * @return true if extraction succeeded
     */
    static bool extractCertificates(const std::vector<std::uint8_t>& signer_info_bytes,
                                   std::vector<std::vector<std::uint8_t>>& certificates);
};

} // namespace apksig

