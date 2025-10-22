#include "Utils.h"
#include "Connection.h"
#include "Protocol.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <filesystem>
#include <iostream>

namespace Utils {

    // =====================
    // server.info
    // =====================
    bool readServerInfo(std::string& ip, uint16_t& port) {
        std::ifstream file("data/server.info");
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open data/server.info");
        }

        // Basic file size check (prevent abuse or huge files)
        const auto size = file.tellg();
        if (size > 1024) {
            throw std::runtime_error("data/server.info too large or malformed");
        }
        file.seekg(0);  // reset to start
        
        std::string line;
        if (!std::getline(file, line) || line.empty()) {
            throw std::runtime_error("data/server.info is empty or malformed");
        }

        std::istringstream iss(line);
        std::string portStr;
        if (!std::getline(iss, ip, ':') || !std::getline(iss, portStr)) {
            throw std::runtime_error("Invalid format in data/server.info (expected IP:PORT)");
        }

        try {
            int p = std::stoi(portStr);                      // store as int first
            if (p < 0 || p > 65535)                          // range validation
                throw std::runtime_error("Port number out of range (0–65535)");
            port = static_cast<uint16_t>(p);
        }
        catch (...) {
            throw std::runtime_error("Invalid port number in data/server.info");
        }

        return true;
    }

    // =====================
    // UUID <-> hex conversion
    // =====================
    std::string uuidToHex(const std::array<uint8_t, 16>& uuid) {
        std::ostringstream oss;
        for (auto b : uuid)
            oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
        return oss.str();
    }

    std::array<uint8_t, 16> hexToUUID(const std::string& hex) {
        if (hex.size() != 32) {
            throw std::runtime_error("Invalid UUID hex length: " + std::to_string(hex.size()));
        }

        std::array<uint8_t, 16> uuid{};
        for (size_t i = 0; i < 16; ++i) {
            const std::string byteStr = hex.substr(i * 2, 2);
            uuid[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }
        return uuid;
    }

    // =====================
    // Network I/O helpers
    // =====================
    bool sendRequestHeader(Connection& conn, RequestHeader& hdr) {
        // Compile-time sanity check for struct size
        static_assert(sizeof(RequestHeader) == REQ_HEADER_SIZE, "Unexpected RequestHeader size");
        
        hdr.code = Protocol::toLittleEndian16(hdr.code);
        hdr.payloadSize = Protocol::toLittleEndian32(hdr.payloadSize);
        return conn.sendAll(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)); // reinterpret_cast, may throw internally
    }

    bool recvResponseHeader(Connection& conn, ResponseHeader& hdr) {
        // Compile-time sanity check for struct size
        static_assert(sizeof(ResponseHeader) == RES_HEADER_SIZE, "Unexpected ResponseHeader size");
        
        conn.recvAll(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)); // reinterpret_cast, may throw internally
        hdr.code = Protocol::fromLittleEndian16(hdr.code);
        hdr.payloadSize = Protocol::fromLittleEndian32(hdr.payloadSize);
        return true;
    }

    bool sendPayload(Connection& conn, const std::vector<uint8_t>& data) {
        if (data.empty()) return true;
        return conn.sendAll(data.data(), data.size());
    }

    bool recvPayload(Connection& conn, std::vector<uint8_t>& out, uint32_t size) {
        if (size == 0) return true;
        out.resize(size);
        return conn.recvAll(out.data(), size);
    }

} // namespace Utils
