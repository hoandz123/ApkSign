#include "apksig/v2_v3_parser.hpp"
#include "apksig/signature_scheme.hpp"
#include "apksig/signing_block.hpp"
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <cstring>
#include <android/log.h>
#include <vector>
#include <string>

#define LOG_TAG "Loader"
#define LOGI_V23(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE_V23(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace apksig {

namespace {
    // Helper to read uint32 from little-endian bytes
    std::uint32_t readUint32LE(const std::uint8_t* data) {
        return static_cast<std::uint32_t>(data[0]) |
               (static_cast<std::uint32_t>(data[1]) << 8) |
               (static_cast<std::uint32_t>(data[2]) << 16) |
               (static_cast<std::uint32_t>(data[3]) << 24);
    }
    
    // Helper to read uint64 from little-endian bytes
    std::uint64_t readUint64LE(const std::uint8_t* data) {
        return static_cast<std::uint64_t>(data[0]) |
               (static_cast<std::uint64_t>(data[1]) << 8) |
               (static_cast<std::uint64_t>(data[2]) << 16) |
               (static_cast<std::uint64_t>(data[3]) << 24) |
               (static_cast<std::uint64_t>(data[4]) << 32) |
               (static_cast<std::uint64_t>(data[5]) << 40) |
               (static_cast<std::uint64_t>(data[6]) << 48) |
               (static_cast<std::uint64_t>(data[7]) << 56);
    }
}

std::unique_ptr<SignatureBlock> V2V3Parser::parseV2(const std::vector<std::uint8_t>& block_data) {
    return parse(block_data, APK_SIGNATURE_SCHEME_V2_ID);
}

std::unique_ptr<SignatureBlock> V2V3Parser::parseV3(const std::vector<std::uint8_t>& block_data) {
    return parse(block_data, APK_SIGNATURE_SCHEME_V3_ID);
}

namespace {
    // Helper to encode bytes to base64
    std::string encodeBase64(const std::vector<std::uint8_t>& data) {
        if (data.empty()) {
            return "";
        }
        
        BIO* bio = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_push(b64, bio);
        
        BIO_write(bio, data.data(), static_cast<int>(data.size()));
        BIO_flush(bio);
        
        char* encoded_data = nullptr;
        long encoded_len = BIO_get_mem_data(bio, &encoded_data);
        
        std::string result(encoded_data, encoded_len);
        
        BIO_free_all(bio);
        
        return result;
    }
    
    bool readLengthPrefixedSlice(const std::vector<std::uint8_t>& data, std::size_t& offset,
                                 std::vector<std::uint8_t>& result, const char* context = nullptr) {
        if (offset + 4 > data.size()) {
            return false;
        }
        std::uint32_t length = readUint32LE(data.data() + offset);
        offset += 4;
        
        if (length > data.size() - offset) {
            return false;
        }
        
        result.resize(length);
        std::copy(data.begin() + offset, data.begin() + offset + length, result.begin());
        offset += length;
        return true;
    }
}

std::unique_ptr<SignatureBlock> V2V3Parser::parse(const std::vector<std::uint8_t>& block_data,
                                                   std::uint32_t scheme_id) {
    if (block_data.empty()) {
        LOGE_V23("Block data is empty");
        return nullptr;
    }
    
    LOGI_V23("Parsing signature block, scheme_id=0x%08x, size=%zu", scheme_id, block_data.size());
    
    // v2/v3 signature block format (from V2SchemeSigner.java):
    // v2_block = encodeAsSequenceOfLengthPrefixedElements([encodeAsSequenceOfLengthPrefixedElements(signerBlocks)])
    // Format: [uint32 outer_length][uint32 inner_length][length-prefixed signer1][length-prefixed signer2]...
    // Each signer: [length-prefixed signed_data][length-prefixed signatures][length-prefixed public_key]
    // Each signature: [length-prefixed][uint32 algorithm_id][length-prefixed signature_bytes]
    
    std::size_t offset = 0;
    
    // Read outer length (first layer)
    if (offset + 4 > block_data.size()) {
        LOGE_V23("Not enough data for outer length");
        return nullptr;
    }
    std::uint32_t outer_length = readUint32LE(block_data.data() + offset);
    offset += 4;
    
    LOGI_V23("Outer length: %u, block_data remaining: %zu, block_data total: %zu", 
             outer_length, block_data.size() - offset, block_data.size());
    
    if (outer_length > block_data.size() - offset) {
        LOGE_V23("Outer length %u exceeds remaining data %zu", outer_length, block_data.size() - offset);
        return nullptr;
    }
    
    // Read inner length (second layer)
    if (offset + 4 > block_data.size()) {
        LOGE_V23("Not enough data for inner length");
        return nullptr;
    }
    std::uint32_t inner_length = readUint32LE(block_data.data() + offset);
    offset += 4;
    
    LOGI_V23("Inner length: %u, block_data remaining: %zu", inner_length, block_data.size() - offset);
    
    if (inner_length > block_data.size() - offset) {
        LOGE_V23("Inner length %u exceeds remaining data %zu", inner_length, block_data.size() - offset);
        return nullptr;
    }
    
    if (inner_length == 0) {
        LOGE_V23("Inner data is empty");
        return nullptr;
    }
    
    auto signature_block = std::make_unique<SignatureBlock>();
    signature_block->scheme_id = scheme_id;
    
    std::size_t signers_offset = offset;
    int signer_count = 0;
    
    while (signers_offset < offset + inner_length) {
        Signer signer;
        
        // Read length-prefixed signed_data from block_data
        char context_buf[64];
        snprintf(context_buf, sizeof(context_buf), "signer[%d].signed_data", signer_count);
        if (!readLengthPrefixedSlice(block_data, signers_offset, signer.signed_data, context_buf)) {
            LOGE_V23("Failed to read signed_data for signer %d at offset %zu", signer_count, signers_offset);
            break;
        }
        
        LOGI_V23("Signer %d: signed_data_size=%zu, signers_offset=%zu, block_data remaining=%zu", 
                 signer_count, signer.signed_data.size(), signers_offset, block_data.size() - signers_offset);
        
        // V3 format has minSdkVersion and maxSdkVersion between signed_data and signatures
        if (scheme_id == APK_SIGNATURE_SCHEME_V3_ID) {
            if (signers_offset + 8 > block_data.size()) {
                LOGE_V23("Not enough data for minSdkVersion/maxSdkVersion for signer %d", signer_count);
                break;
            }
            std::uint32_t min_sdk_version = readUint32LE(block_data.data() + signers_offset);
            std::uint32_t max_sdk_version = readUint32LE(block_data.data() + signers_offset + 4);
            signers_offset += 8;
            LOGI_V23("Signer %d: minSdkVersion=%u, maxSdkVersion=%u", signer_count, min_sdk_version, max_sdk_version);
        }
        
        // Read length-prefixed signatures from block_data
        snprintf(context_buf, sizeof(context_buf), "signer[%d].signatures", signer_count);
        std::vector<std::uint8_t> signatures_data;
        if (!readLengthPrefixedSlice(block_data, signers_offset, signatures_data, context_buf)) {
            LOGE_V23("Failed to read signatures for signer %d at offset %zu (block_data_size=%zu, remaining=%zu)", 
                     signer_count, signers_offset, block_data.size(), block_data.size() - signers_offset);
            break;
        }
        
        LOGI_V23("Signer %d: signatures_data_size=%zu", signer_count, signatures_data.size());
        
        std::size_t sigs_offset = 0;
        int sig_count = 0;
        while (sigs_offset < signatures_data.size()) {
            snprintf(context_buf, sizeof(context_buf), "signer[%d].signature[%d]", signer_count, sig_count);
            std::vector<std::uint8_t> signature_block_data;
            if (!readLengthPrefixedSlice(signatures_data, sigs_offset, signature_block_data, context_buf)) {
                break;
            }
            
            if (signature_block_data.size() < 4) {
                LOGE_V23("Signature block too small: %zu", signature_block_data.size());
                break;
            }
            
            std::uint32_t algorithm_id = readUint32LE(signature_block_data.data());
            LOGI_V23("Signer %d, Signature %d: algorithm_id=0x%08x", signer_count, sig_count, algorithm_id);
            
            std::size_t sig_block_offset = 4;
            std::vector<std::uint8_t> signature_bytes;
            if (!readLengthPrefixedSlice(signature_block_data, sig_block_offset, signature_bytes, "signature_bytes")) {
                if (sig_block_offset < signature_block_data.size()) {
                    signature_bytes.assign(signature_block_data.begin() + sig_block_offset,
                                          signature_block_data.end());
                }
            }
            
            // Log signature block (like Java Signature class) as base64
            // Format: [length-prefixed][uint32 algorithm_id][length-prefixed signature_bytes]
            if (!signature_block_data.empty()) {
                std::string signature_block_base64 = encodeBase64(signature_block_data);
                LOGI_V23("Signer %d, Signature %d (base64): %s", signer_count, sig_count, signature_block_base64.c_str());
            }
            
            // Also log just signature_bytes for reference
            if (!signature_bytes.empty()) {
                std::string signature_bytes_base64 = encodeBase64(signature_bytes);
                LOGI_V23("Signer %d, Signature %d bytes (base64): %s", signer_count, sig_count, signature_bytes_base64.c_str());
            }
            
            signer.signature_algorithms.push_back(algorithm_id);
            signer.signatures.push_back(std::move(signature_bytes));
            sig_count++;
        }
        
        // Read length-prefixed public_key from block_data
        snprintf(context_buf, sizeof(context_buf), "signer[%d].public_key", signer_count);
        std::vector<std::uint8_t> public_key;
        if (!readLengthPrefixedSlice(block_data, signers_offset, public_key, context_buf)) {
            LOGE_V23("Failed to read public_key for signer %d at offset %zu", signer_count, signers_offset);
            break;
        }
        
        LOGI_V23("Signer %d: public_key_size=%zu", signer_count, public_key.size());
        
        // Extract certificates from signed_data
        // signed_data format: [length-prefixed digests][length-prefixed certificates][length-prefixed additional_attributes]
        std::size_t signed_data_offset = 0;
        
        // Skip digests
        std::vector<std::uint8_t> digests;
        if (!readLengthPrefixedSlice(signer.signed_data, signed_data_offset, digests, "digests")) {
            LOGE_V23("Failed to read digests from signed_data");
        }
        
            // Read certificates
            std::vector<std::uint8_t> certificates_data;
            if (readLengthPrefixedSlice(signer.signed_data, signed_data_offset, certificates_data, "certificates")) {
                std::size_t certs_offset = 0;
                int cert_count = 0;
                while (certs_offset < certificates_data.size()) {
                    std::vector<std::uint8_t> cert_der;
                    char cert_context[64];
                    snprintf(cert_context, sizeof(cert_context), "certificate[%d]", cert_count);
                    if (readLengthPrefixedSlice(certificates_data, certs_offset, cert_der, cert_context)) {
                        // Log certificate as base64 (like Java Signature class)
                        if (!cert_der.empty()) {
                            std::string cert_base64 = encodeBase64(cert_der);
                            LOGI_V23("Signer %d, Certificate %d (base64): %s", signer_count, cert_count, cert_base64.c_str());
                        }
                        signer.certificates.push_back(std::move(cert_der));
                        cert_count++;
                    } else {
                        break;
                    }
                }
                LOGI_V23("Signer %d: extracted %zu certificates from signed_data", signer_count, signer.certificates.size());
            } else {
                LOGE_V23("Failed to read certificates from signed_data");
            }
        
        signature_block->signers.push_back(std::move(signer));
        signer_count++;
        
        if (signer_count > 16) {
            LOGE_V23("Too many signers: %d", signer_count);
            break;
        }
    }
    
    LOGI_V23("Successfully parsed signature block with %zu signers", signature_block->signers.size());
    return signature_block;
}

bool V2V3Parser::parseSignedData(const std::vector<std::uint8_t>& signed_data_bytes,
                                 std::vector<Signer>& signers) {
    // This function is not currently used - certificate extraction is done
    // directly via extractCertificates. Keeping for potential future use.
    (void)signed_data_bytes;
    (void)signers;
    return false;
}

bool V2V3Parser::parseSignerInfo(const std::vector<std::uint8_t>& signer_info_bytes,
                                 Signer& signer) {
    // This would require detailed ASN.1 parsing of SignerInfo structure
    // For now, we use OpenSSL's PKCS7 parsing which handles this
    return false;  // Not fully implemented - using parseSignedData instead
}

bool V2V3Parser::extractCertificates(const std::vector<std::uint8_t>& signer_info_bytes,
                                     std::vector<std::vector<std::uint8_t>>& certificates) {
    // Try to parse as PKCS7 to extract certificates
    const unsigned char* data = signer_info_bytes.data();
    PKCS7* pkcs7 = d2i_PKCS7(nullptr, &data, static_cast<long>(signer_info_bytes.size()));
    
    if (!pkcs7) {
        return false;
    }
    
    bool success = false;
    
    if (OBJ_obj2nid(pkcs7->type) == NID_pkcs7_signed) {
        PKCS7_SIGNED* signed_data = pkcs7->d.sign;
        if (signed_data) {
            STACK_OF(X509)* certs = signed_data->cert;
            if (certs) {
                int cert_count = sk_X509_num(certs);
                for (int i = 0; i < cert_count; ++i) {
                    X509* cert = sk_X509_value(certs, i);
                    if (cert) {
                        unsigned char* der = nullptr;
                        int der_len = i2d_X509(cert, &der);
                        if (der_len > 0 && der) {
                            certificates.emplace_back(der, der + der_len);
                            OPENSSL_free(der);
                            success = true;
                        }
                    }
                }
            }
        }
    }
    
    PKCS7_free(pkcs7);
    return success;
}

} // namespace apksig

