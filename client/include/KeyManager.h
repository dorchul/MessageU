#pragma once
#include <string>
#include <array>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include "AESWrapper.h"

class KeyManager {
public:
    bool hasPublicKey(const std::string& peer) const { return m_pubKeys.count(peer) > 0; }
    void cachePublicKey(const std::string& peer, const std::vector<uint8_t>& key) { m_pubKeys[peer] = key; }
    const std::vector<uint8_t>& getPublicKey(const std::string& peer) const { return m_pubKeys.at(peer); }

    bool hasSymmetricKey(const std::string& peer) const { return m_symKeys.count(peer) > 0; }
    void cacheSymmetricKey(const std::string& peer, const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key) { m_symKeys[peer] = key; }

private:
    std::unordered_map<std::string, std::vector<uint8_t>> m_pubKeys;
    std::unordered_map<std::string, std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>> m_symKeys;
};
