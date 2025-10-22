#include "KeyManager.h"
#include "Protocol.h"

#include <algorithm>
#include <stdexcept>

// ===============================
// Public keys
// ===============================
bool KeyManager::hasPublicKey(const std::string& uuidHex) const {
    return m_pubKeys.find(uuidHex) != m_pubKeys.end();
}

std::vector<uint8_t> KeyManager::getPublicKey(const std::string& uuidHex) const {
    auto it = m_pubKeys.find(uuidHex);
    if (it == m_pubKeys.end())
        throw std::runtime_error("Public key not found for peer: " + uuidHex.substr(0, 8));
    return it->second;
}

void KeyManager::cachePublicKey(const std::string& uuidHex, const std::vector<uint8_t>& pubKey) {
    if (pubKey.size() > PUBKEY_SIZE)                                   // size guard
        throw std::runtime_error("KeyManager: public key exceeds PUBKEY_SIZE");
    m_pubKeys[uuidHex] = pubKey;
}

// ===============================
// Symmetric AES keys
// ===============================
bool KeyManager::hasSymmetricKey(const std::string& uuidHex) const {
    return m_symKeys.find(uuidHex) != m_symKeys.end();
}

std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>
KeyManager::getSymmetricKey(const std::string& uuidHex) const {
    auto it = m_symKeys.find(uuidHex);
    if (it == m_symKeys.end())
        throw std::runtime_error("Symmetric key not found in memory for peer: " + uuidHex.substr(0, 8));
    return it->second;
}

void KeyManager::cacheSymmetricKey(
    const std::string& uuidHex,
    const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key)
{
    if (key.size() != AESWrapper::DEFAULT_KEYLENGTH)                   // redundant safety
        throw std::runtime_error("KeyManager: invalid AES key length");

    m_symKeys[uuidHex] = key;
}

KeyManager::~KeyManager() noexcept {
    for (auto& [uuid, key] : m_symKeys)
        std::fill_n(key.begin(), key.size(), 0);                      // clear RAM
}