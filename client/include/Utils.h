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


    // UUID array -> lowercase hex
    std::string uuidToHex(const std::array<uint8_t, 16>& uuid);

    // NEW: Generate RSA-1024. Returns DER bytes:
    // - privateKeyDER: PKCS#1 DER (no PEM headers)
    // - publicKeyDER: X.509 SubjectPublicKeyInfo (DER)
    // Returns true on success.
    bool generateRSA1024(std::vector<uint8_t>& privateKeyDER,
        std::vector<uint8_t>& publicKeyDER);
}
