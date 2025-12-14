#include "apksig/apk_reader.hpp"
#include <fstream>
#include <stdexcept>
#include <algorithm>

namespace apksig {

std::uint16_t DataSource::readUint16(std::uint64_t offset) const {
    std::uint8_t buffer[2];
    if (read(offset, 2, buffer) != 2) {
        throw std::runtime_error("Failed to read uint16");
    }
    return static_cast<std::uint16_t>(buffer[0]) |
           (static_cast<std::uint16_t>(buffer[1]) << 8);
}

std::uint32_t DataSource::readUint32(std::uint64_t offset) const {
    std::uint8_t buffer[4];
    if (read(offset, 4, buffer) != 4) {
        throw std::runtime_error("Failed to read uint32");
    }
    return static_cast<std::uint32_t>(buffer[0]) |
           (static_cast<std::uint32_t>(buffer[1]) << 8) |
           (static_cast<std::uint32_t>(buffer[2]) << 16) |
           (static_cast<std::uint32_t>(buffer[3]) << 24);
}

std::uint64_t DataSource::readUint64(std::uint64_t offset) const {
    std::uint8_t buffer[8];
    if (read(offset, 8, buffer) != 8) {
        throw std::runtime_error("Failed to read uint64");
    }
    return static_cast<std::uint64_t>(buffer[0]) |
           (static_cast<std::uint64_t>(buffer[1]) << 8) |
           (static_cast<std::uint64_t>(buffer[2]) << 16) |
           (static_cast<std::uint64_t>(buffer[3]) << 24) |
           (static_cast<std::uint64_t>(buffer[4]) << 32) |
           (static_cast<std::uint64_t>(buffer[5]) << 40) |
           (static_cast<std::uint64_t>(buffer[6]) << 48) |
           (static_cast<std::uint64_t>(buffer[7]) << 56);
}

FileDataSource::FileDataSource(const std::string& filepath)
    : filepath_(filepath) {
    file_.open(filepath, std::ios::binary | std::ios::ate);
    if (!file_.is_open()) {
        throw std::runtime_error("Failed to open file: " + filepath);
    }
    
    // Get file size
    file_.seekg(0, std::ios::end);
    std::streampos pos = file_.tellg();
    if (pos < 0) {
        throw std::runtime_error("Failed to determine file size");
    }
    file_size_ = static_cast<std::uint64_t>(pos);
}

std::size_t FileDataSource::read(std::uint64_t offset, std::size_t size, std::uint8_t* buffer) const {
    if (offset >= file_size_) {
        return 0;
    }
    
    // Clamp size to available data
    std::size_t available = static_cast<std::size_t>(file_size_ - offset);
    std::size_t to_read = std::min(size, available);
    
    // Clear any error flags and seek to position
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!file_.good()) {
        return 0;
    }
    
    file_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(to_read));
    std::size_t bytes_read = static_cast<std::size_t>(file_.gcount());
    
    // Clear error flags after read (EOF is OK)
    if (file_.eof()) {
        file_.clear();
    }
    
    return bytes_read;
}

std::uint64_t FileDataSource::size() const {
    return file_size_;
}

} // namespace apksig

