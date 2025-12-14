#include "apksig/digest_verifier.hpp"
#include "apksig/signing_block.hpp"
#include "apksig/signature_scheme.hpp"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>

namespace apksig {

ContentDigests DigestVerifier::computeDigests(const DataSource& source,
                                              const SigningBlockLocation& signing_block_location) {
    ContentDigests digests;
    digests.sha256 = computeSha256(source, signing_block_location);
    digests.sha512 = computeSha512(source, signing_block_location);
    return digests;
}

bool DigestVerifier::verifyDigests(const ContentDigests& computed_digests,
                                   const SignatureBlock& signature_block) {
    // Extract expected digests from signed data
    ContentDigests expected_digests = extractDigestsFromSignedData(signature_block);
    
    // Compare SHA-256
    if (!computed_digests.sha256.empty() && !expected_digests.sha256.empty()) {
        if (computed_digests.sha256 != expected_digests.sha256) {
            return false;
        }
    }
    
    // Compare SHA-512
    if (!computed_digests.sha512.empty() && !expected_digests.sha512.empty()) {
        if (computed_digests.sha512 != expected_digests.sha512) {
            return false;
        }
    }
    
    return true;
}

std::vector<std::uint8_t> DigestVerifier::computeSha256(const DataSource& source,
                                                        const SigningBlockLocation& location) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return {};
    }
    
    const EVP_MD* md = EVP_sha256();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    
    // Hash all bytes before the signing block
    std::uint64_t before_size = location.offset;
    std::vector<std::uint8_t> buffer(64 * 1024);  // 64KB buffer
    
    for (std::uint64_t offset = 0; offset < before_size; ) {
        std::size_t to_read = static_cast<std::size_t>(
            std::min(static_cast<std::uint64_t>(buffer.size()), before_size - offset));
        std::size_t read = source.read(offset, to_read, buffer.data());
        
        if (read == 0) {
            break;
        }
        
        if (EVP_DigestUpdate(ctx, buffer.data(), read) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        
        offset += read;
    }
    
    // Hash all bytes after the signing block (Central Directory + EOCD)
    std::uint64_t after_start = location.offset + location.size + 24;  // +24 for size fields and magic
    std::uint64_t file_size = source.size();
    
    for (std::uint64_t offset = after_start; offset < file_size; ) {
        std::size_t to_read = static_cast<std::size_t>(
            std::min(static_cast<std::uint64_t>(buffer.size()), file_size - offset));
        std::size_t read = source.read(offset, to_read, buffer.data());
        
        if (read == 0) {
            break;
        }
        
        if (EVP_DigestUpdate(ctx, buffer.data(), read) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        
        offset += read;
    }
    
    // Finalize digest
    std::vector<std::uint8_t> digest(SHA256_DIGEST_LENGTH);
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    
    EVP_MD_CTX_free(ctx);
    return digest;
}

std::vector<std::uint8_t> DigestVerifier::computeSha512(const DataSource& source,
                                                        const SigningBlockLocation& location) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return {};
    }
    
    const EVP_MD* md = EVP_sha512();
    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    
    // Hash all bytes before the signing block
    std::uint64_t before_size = location.offset;
    std::vector<std::uint8_t> buffer(64 * 1024);  // 64KB buffer
    
    for (std::uint64_t offset = 0; offset < before_size; ) {
        std::size_t to_read = static_cast<std::size_t>(
            std::min(static_cast<std::uint64_t>(buffer.size()), before_size - offset));
        std::size_t read = source.read(offset, to_read, buffer.data());
        
        if (read == 0) {
            break;
        }
        
        if (EVP_DigestUpdate(ctx, buffer.data(), read) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        
        offset += read;
    }
    
    // Hash all bytes after the signing block (Central Directory + EOCD)
    std::uint64_t after_start = location.offset + location.size + 24;  // +24 for size fields and magic
    std::uint64_t file_size = source.size();
    
    for (std::uint64_t offset = after_start; offset < file_size; ) {
        std::size_t to_read = static_cast<std::size_t>(
            std::min(static_cast<std::uint64_t>(buffer.size()), file_size - offset));
        std::size_t read = source.read(offset, to_read, buffer.data());
        
        if (read == 0) {
            break;
        }
        
        if (EVP_DigestUpdate(ctx, buffer.data(), read) != 1) {
            EVP_MD_CTX_free(ctx);
            return {};
        }
        
        offset += read;
    }
    
    // Finalize digest
    std::vector<std::uint8_t> digest(SHA512_DIGEST_LENGTH);
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    
    EVP_MD_CTX_free(ctx);
    return digest;
}

ContentDigests DigestVerifier::extractDigestsFromSignedData(const SignatureBlock& signature_block) {
    ContentDigests digests;
    
    // The signed data contains digests in ASN.1 format
    // This is a simplified extraction - full implementation would parse the ASN.1 structure
    // to find the ContentDigest attributes
    
    // For now, we'll need to parse the SignedData structure more carefully
    // This is a placeholder - actual implementation would use ASN.1 parsing
    
    return digests;
}

} // namespace apksig

