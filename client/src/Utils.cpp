#include "Utils.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <array>
#include <filesystem>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/queue.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>

// ===== Base64 (encode only, single-line) =====
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
    // me.info (spec: 3 lines)
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

        // 3. Private key base64
        std::string priv64 = base64Encode(privateKey.data(), privateKey.size());
        f << priv64 << "\n";

        return true;
    }


    // =====================
    // UUID -> hex string
    // =====================
    std::string uuidToHex(const std::array<uint8_t, 16>& uuid) {
        std::ostringstream oss;
        for (auto b : uuid)
            oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
        return oss.str();
    }

    // =====================
    // RSA key generation (Crypto++)
    // =====================

    bool generateRSA1024(std::vector<uint8_t>& privateKeyDER,
        std::vector<uint8_t>& publicKeyDER) {
        try {
            CryptoPP::AutoSeededRandomPool rng;

            // Generate keypair
            CryptoPP::InvertibleRSAFunction params;
            params.GenerateRandomWithKeySize(rng, 1024);

            CryptoPP::RSA::PrivateKey priv(params);
            CryptoPP::RSA::PublicKey pub(params);

            // ---- Private key (PKCS#1 DER) ----
            {
                CryptoPP::ByteQueue q;
                priv.Save(q);
                privateKeyDER.resize((size_t)q.CurrentSize());
                q.Get(privateKeyDER.data(), privateKeyDER.size());
            }

            // ---- Public key (X.509 DER → truncated/padded to 160B) ----
            {
                CryptoPP::ByteQueue q;
                pub.Save(q);
                std::vector<uint8_t> der;
                der.resize((size_t)q.CurrentSize());
                q.Get(der.data(), der.size());

                // If longer than 160B, take the first 160; if shorter, pad with zeros
                publicKeyDER = der;
                if (publicKeyDER.size() > 160)
                    publicKeyDER.resize(160);
                else if (publicKeyDER.size() < 160)
                    publicKeyDER.insert(publicKeyDER.end(), 160 - publicKeyDER.size(), 0);
            }

            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "generateRSA1024() failed: " << e.what() << std::endl;
            return false;
        }
    }

} // namespace Utils
