#pragma once
#include <string>
#include <array>

class IdentityManager {
public:
    IdentityManager() = default;

    bool load(const std::string& dataDir,
        const std::string& name,
        std::array<uint8_t, 16>& clientId);

    bool save(const std::string& dataDir,
        const std::string& name,
        const std::array<uint8_t, 16>& clientId,
        const std::string& privKeyDER);

    const std::string& getPrivateKey() const { return m_privateKey; }

private:
    std::string m_privateKey; // binary DER form (as returned by RSAPrivateWrapper)
};
