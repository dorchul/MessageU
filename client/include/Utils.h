#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>

namespace Utils {

    // Read "IP:PORT" from data/server.info
    bool readServerInfo(std::string& ip, uint16_t& port);

    // Save me.info (3 lines): Name, UUID hex (32), PrivateKey Base64
    bool saveMeInfo(const std::string& name,
        const std::array<uint8_t, 16>& id,
        const std::vector<uint8_t>& privateKey,
        const std::string& dataDir);

    // Load me.info (3 lines): Name, UUID hex (32), PrivateKey Base64
    bool loadMeInfo(std::string& name,
        std::array<uint8_t, 16>& uuid,
        std::vector<uint8_t>& privateKey,
        const std::string& dataDir);

    // UUID array -> lowercase hex
    std::string uuidToHex(const std::array<uint8_t, 16>& uuid);

    // Hex string (32 chars) → UUID array (16 bytes)
    std::array<uint8_t, 16> hexToUUID(const std::string& hex);


}
