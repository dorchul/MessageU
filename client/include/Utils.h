#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <iostream>

// Forward declarations
struct RequestHeader;
struct ResponseHeader;
class Connection;

namespace Utils {

    // Read "IP:PORT" from data/server.info
    bool readServerInfo(std::string& ip, uint16_t& port);

    // UUID array -> lowercase hex
    std::string uuidToHex(const std::array<uint8_t, 16>& uuid);

    // Hex string (32 chars) → UUID array (16 bytes)
    std::array<uint8_t, 16> hexToUUID(const std::string& hex);

    // =====================
    // Network I/O helpers
    // =====================
    bool sendRequestHeader(::Connection& conn, ::RequestHeader& hdr);
    bool recvResponseHeader(::Connection& conn, ::ResponseHeader& hdr);
    bool sendPayload(::Connection& conn, const std::vector<uint8_t>& data);
    bool recvPayload(::Connection& conn, std::vector<uint8_t>& out, uint32_t size);
}