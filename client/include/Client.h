#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <iostream>
#include <unordered_map>

#include "Protocol.h"
#include "Utils.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"

class Connection;

// ===============================
// PendingMessage structure
// ===============================
struct PendingMessage {
    std::array<uint8_t, 16> fromId;
    uint32_t id;
    uint8_t type;
    std::vector<uint8_t> content;
};

// ===============================
// DecodedMessage structure
// ===============================
struct DecodedMessage {
    std::string fromHex;
    MessageType type;
    std::string text;  // decrypted text or message info
};

// ===============================
// Client class
// ===============================
class Client {
public:
    explicit Client(Connection& conn, const std::string& dataDir)
        : m_conn(conn)
    {
        std::string name;
        std::vector<uint8_t> privKey;
        if (Utils::loadMeInfo(name, m_clientId, privKey, dataDir)) {
            m_name = name;
            std::cout << "[Client] Loaded UUID from " << dataDir << "/me.info\n\n";
        }
        else {
            std::memset(m_clientId.data(), 0, 16);
            std::cout << "[Client] No existing identity found.\n\n";
        }
    }


    // ===== Protocol operations =====
    bool doRegister(const std::string& name, const std::string& dataDir);  // 600
    
    std::vector<std::pair<std::array<uint8_t, 16>, std::string>> requestClientsList(); // 601
    
    std::vector<uint8_t> requestPublicKey(const std::string& targetUUID);  // 602
    
    bool sendMessage(const std::array<uint8_t, 16>& toClient,
        MessageType type,
        const std::vector<uint8_t>& content);                 // 603
    
    std::vector<PendingMessage> requestWaitingMessages();                  // 604

    // ===== Decode & process incoming messages =====
    std::vector<DecodedMessage> decodeMessages(const std::vector<PendingMessage>& msgs);

    // ===== Accessors =====
    const std::array<uint8_t, 16>& id() const { return m_clientId; }
    const std::string& name() const { return m_name; }

    void cacheSymmetricKey(const std::string& peerHex,
        const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key) {
        m_symmKeys[peerHex] = key;
    }

    bool hasSymmetricKey(const std::string& peerHex) const {
        return m_symmKeys.find(peerHex) != m_symmKeys.end();
    }

    std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> getSymmetricKey(const std::string& peerHex) const {
        return m_symmKeys.at(peerHex);
    }


private:
    Connection& m_conn;
    std::array<uint8_t, 16> m_clientId{};
    std::string m_name;
    std::vector<uint8_t> m_pubKey;
    std::unordered_map<std::string, std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>> m_symmKeys;
};
