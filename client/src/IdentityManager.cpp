#include "IdentityManager.h"
#include "Utils.h"
#include "Base64Wrapper.h"
#include <fstream>
#include <iostream>

bool IdentityManager::load(const std::string& dataDir,
    const std::string& name,
    std::array<uint8_t, 16>& clientId)
{
    std::string path = dataDir + "/me.info";
    std::ifstream in(path);
    if (!in.is_open())
        return false;

    std::string fileName, uuidHex, priv64;
    std::getline(in, fileName);
    std::getline(in, uuidHex);
    std::getline(in, priv64);
    in.close();

    if (fileName != name) {
        std::cerr << "[IdentityManager] Name mismatch in me.info\n";
        return false;
    }

    try {
        clientId = Utils::hexToUUID(uuidHex);
    }
    catch (...) {
        std::cerr << "[IdentityManager] Invalid UUID format\n";
        return false;
    }

    try {
        m_privateKey = Base64Wrapper::decode(priv64); // decode back to binary DER
    }
    catch (...) {
        std::cerr << "[IdentityManager] Base64 decode failed\n";
        return false;
    }

    return true;
}

bool IdentityManager::save(const std::string& dataDir,
    const std::string& name,
    const std::array<uint8_t, 16>& clientId,
    const std::string& privKeyDER)
{
    std::string path = dataDir + "/me.info";
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "[IdentityManager] Failed to open " << path << " for writing\n";
        return false;
    }

    std::string uuidHex = Utils::uuidToHex(clientId);
    std::string priv64 = Base64Wrapper::encode(privKeyDER); // binary DER → Base64

    out << name << "\n" << uuidHex << "\n" << priv64 << "\n";
    out.close();

    m_privateKey = privKeyDER;
    return true;
}
