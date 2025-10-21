#pragma once
#include <unordered_map>
#include <array>
#include <vector>
#include <string>
#include "AESWrapper.h"

class KeyManager {
public:
    bool hasPublicKey(const std::string& uuidHex) const;
    std::vector<uint8_t> getPublicKey(const std::string& uuidHex) const;
    void cachePublicKey(const std::string& uuidHex, const std::vector<uint8_t>& pubKey);

    bool hasSymmetricKey(const std::string& uuidHex) const;
    std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> getSymmetricKey(const std::string& uuidHex) const;
    void cacheSymmetricKey(const std::string& uuidHex,
        const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key);

private:
    std::unordered_map<std::string, std::vector<uint8_t>> m_pubKeys;
    std::unordered_map<std::string, std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>> m_symKeys;
};
