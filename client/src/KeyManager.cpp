#include "KeyManager.h"

bool KeyManager::hasPublicKey(const std::string& uuidHex) const {
    return m_pubKeys.find(uuidHex) != m_pubKeys.end();
}

std::vector<uint8_t> KeyManager::getPublicKey(const std::string& uuidHex) const {
    return m_pubKeys.at(uuidHex);
}

void KeyManager::cachePublicKey(const std::string& uuidHex, const std::vector<uint8_t>& pubKey) {
    m_pubKeys[uuidHex] = pubKey;
}

bool KeyManager::hasSymmetricKey(const std::string& uuidHex) const {
    return m_symKeys.find(uuidHex) != m_symKeys.end();
}

std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> KeyManager::getSymmetricKey(const std::string& uuidHex) const {
    return m_symKeys.at(uuidHex);
}

void KeyManager::cacheSymmetricKey(const std::string& uuidHex,
    const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key) {
    m_symKeys[uuidHex] = key;
}
