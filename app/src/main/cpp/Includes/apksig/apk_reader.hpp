#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <fstream>

namespace apksig {

/**
 * Data source interface for reading APK file data without unnecessary copying.
 * Similar to ByteBufferDataSource in Java apksig.
 */
class DataSource {
public:
    virtual ~DataSource() = default;
    
    /**
     * Read data from the source into a buffer.
     * @param offset Starting offset in the source
     * @param size Number of bytes to read
     * @param buffer Output buffer (must be at least 'size' bytes)
     * @return Number of bytes actually read
     */
    virtual std::size_t read(std::uint64_t offset, std::size_t size, std::uint8_t* buffer) const = 0;
    
    /**
     * Get the total size of the data source.
     */
    virtual std::uint64_t size() const = 0;
    
    /**
     * Read a little-endian uint16_t from the specified offset.
     */
    std::uint16_t readUint16(std::uint64_t offset) const;
    
    /**
     * Read a little-endian uint32_t from the specified offset.
     */
    std::uint32_t readUint32(std::uint64_t offset) const;
    
    /**
     * Read a little-endian uint64_t from the specified offset.
     */
    std::uint64_t readUint64(std::uint64_t offset) const;
};

/**
 * File-based data source for reading APK files.
 */
class FileDataSource : public DataSource {
public:
    explicit FileDataSource(const std::string& filepath);
    ~FileDataSource() override = default;
    
    std::size_t read(std::uint64_t offset, std::size_t size, std::uint8_t* buffer) const override;
    std::uint64_t size() const override;
    
private:
    mutable std::ifstream file_;
    std::uint64_t file_size_;
    std::string filepath_;
};

} // namespace apksig

