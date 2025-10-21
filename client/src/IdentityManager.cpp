#include "IdentityManager.h"
#include "Utils.h"
#include "Base64Wrapper.h"
#include <fstream>
#include <stdexcept>
#include <filesystem>

// ===============================
// Load existing identity (me.info)
// ===============================
bool IdentityManager::load(const std::string& dataDir,
    const std::string& name,
    std::array<uint8_t, 16>& clientId)
{
    const std::string path = dataDir + "/me.info";
    std::ifstream in(path);
    if (!in.is_open()) {
        return false;
    }


    std::string fileName, uuidHex, priv64;
    if (!std::getline(in, fileName) ||
        !std::getline(in, uuidHex) ||
        !std::getline(in, priv64))
    {
        throw std::runtime_error("Invalid format in identity file: " + path);
    }
    in.close();

    if (fileName != name)
        throw std::runtime_error("Name mismatch in identity file (expected " + name + ")");

    clientId = Utils::hexToUUID(uuidHex); // may throw from Utils

    try {
        m_privateKey = Base64Wrapper::decode(priv64); // decode back to binary DER
    }
    catch (...) {
        throw std::runtime_error("Base64 decoding failed while loading identity");
    }

    return true;
}

// ===============================
// Save identity (me.info)
// ===============================
bool IdentityManager::save(const std::string& dataDir,
    const std::string& name,
    const std::array<uint8_t, 16>& clientId,
    const std::string& privKeyDER)
{
    std::filesystem::create_directories(dataDir);
    const std::string path = dataDir + "/me.info";
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open())
        throw std::runtime_error("Failed to open " + path + " for writing");

    std::string uuidHex = Utils::uuidToHex(clientId);
    std::string priv64 = Base64Wrapper::encode(privKeyDER);

    out << name << "\n" << uuidHex << "\n" << priv64 << "\n";
    if (!out.good())
        throw std::runtime_error("Failed to write identity data to " + path);

    out.close();
    m_privateKey = privKeyDER;
    return true;
}
