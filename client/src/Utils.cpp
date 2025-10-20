#include "Utils.h"
#include "Connection.h"
#include "Protocol.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <array>
#include <filesystem>
#include <iostream>

static const char* B64CHARS =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64Encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t n = (uint32_t(data[i]) << 16) |
            (uint32_t(data[i + 1]) << 8) |
            (uint32_t(data[i + 2]));
        out.push_back(B64CHARS[(n >> 18) & 63]);
        out.push_back(B64CHARS[(n >> 12) & 63]);
        out.push_back(B64CHARS[(n >> 6) & 63]);
        out.push_back(B64CHARS[n & 63]);
        i += 3;
    }
    if (i < len) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= (uint32_t(data[i + 1]) << 8);
        out.push_back(B64CHARS[(n >> 18) & 63]);
        out.push_back(B64CHARS[(n >> 12) & 63]);
        if (i + 1 < len) out.push_back(B64CHARS[(n >> 6) & 63]);
        else out.push_back('=');
        out.push_back('=');
    }
    return out;
}

namespace Utils {

    // =====================
    // server.info
    // =====================
    bool readServerInfo(std::string& ip, uint16_t& port) {
        std::ifstream file("data/server.info");
        if (!file.is_open()) return false;

        std::string line;
        std::getline(file, line);
        file.close();

        std::istringstream iss(line);
        std::string portStr;
        if (!std::getline(iss, ip, ':')) return false;
        if (!std::getline(iss, portStr)) return false;

        port = static_cast<uint16_t>(std::stoi(portStr));
        return true;
    }

    // =====================
    // me.info
    // =====================
    bool saveMeInfo(const std::string& name,
        const std::array<uint8_t, 16>& id,
        const std::vector<uint8_t>& privateKey,
        const std::string& dataDir)
    {
        std::filesystem::create_directories(dataDir);
        std::ofstream f(dataDir + "/me.info", std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;

        // 1. Name
        f << name << "\n";

        // 2. UUID hex
        std::ostringstream uuidHex;
        for (auto b : id)
            uuidHex << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
        f << uuidHex.str() << "\n";

        // 3. Private key base64 (DER)
        std::string priv64 = base64Encode(privateKey.data(), privateKey.size());
        f << priv64 << "\n";

        return true;
    }

    bool loadMeInfo(std::string& name,
        std::array<uint8_t, 16>& uuid,
        std::vector<uint8_t>& privateKey,
        const std::string& dataDir)
    {
        std::ifstream f(dataDir + "/me.info");
        if (!f.is_open()) return false;

        std::string uuidHex, priv64;
        if (!std::getline(f, name)) return false;
        if (!std::getline(f, uuidHex)) return false;
        if (!std::getline(f, priv64)) return false;

        // Parse UUID hex → bytes
        if (uuidHex.size() != 32) return false;
        for (size_t i = 0; i < 16; ++i) {
            std::string byteStr = uuidHex.substr(i * 2, 2);
            uuid[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        }

        // Decode base64 private key
        auto decode64 = [](const std::string& in) -> std::vector<uint8_t> {
            static const std::string chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::vector<uint8_t> out;
            int val = 0, valb = -8;
            for (unsigned char c : in) {
                if (isspace(c) || c == '=') continue;
                int idx = chars.find(c);
                if (idx == std::string::npos) break;
                val = (val << 6) + idx;
                valb += 6;
                if (valb >= 0) {
                    out.push_back(uint8_t((val >> valb) & 0xFF));
                    valb -= 8;
                }
            }
            return out;
        };
        privateKey = decode64(priv64);
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
        std::array<uint8_t, 16> uuid{};
        if (hex.size() != 32) {
            std::cerr << "[Utils] Invalid UUID hex length: " << hex.size() << " (expected 32)\n";
            return uuid; // all zeros
        }
        for (size_t i = 0; i < 16; ++i) {
            std::string byteStr = hex.substr(i * 2, 2);
            uuid[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }
        return uuid;
    }

    // =====================
    // Network I/O helpers
    // =====================
    bool sendRequestHeader(Connection& conn, RequestHeader& hdr) {
        hdr.code = Protocol::toLittleEndian16(hdr.code);
        hdr.payloadSize = Protocol::toLittleEndian32(hdr.payloadSize);
        return conn.sendAll(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr));
    }

    bool recvResponseHeader(Connection& conn, ResponseHeader& hdr) {
        if (!conn.recvAll(reinterpret_cast<uint8_t*>(&hdr), sizeof(hdr)))
            return false;
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
