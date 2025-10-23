#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <unordered_map>

#include "Protocol.h"
#include "IdentityManager.h"
#include "KeyManager.h"

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
    Client(Connection& conn, const std::string& name, const std::string& dataDir);

    // ===== Protocol operations =====
    bool doRegister(const std::string& dataDir);  // 600
    
    std::vector<std::pair<std::array<uint8_t, 16>, std::string>> requestClientsList() const; // 601
    
    std::vector<uint8_t> requestPublicKey(const std::string& targetUUID);  // 602
    
    bool sendMessage(const std::array<uint8_t, 16>& toClient,
        MessageType type,
        const std::vector<uint8_t>& content);  // 603
    
    std::vector<PendingMessage> requestWaitingMessages() const;  // 604

    // Cache/update the UUID to name map from a freshly fetched clients list
    void cacheClientDirectory(const std::vector<std::pair<std::array<uint8_t, 16>, std::string>>& list);
                                                                 // ===== Decode & process incoming messages =====
    std::vector<DecodedMessage> fetchMessages();  // 604: fetch + decrypt

    // ===== Accessors =====
    const std::array<uint8_t, 16>& id() const noexcept { return m_clientId; }
    const std::string& name() const noexcept { return m_name; }

    std::string nameFor(const std::string& uuidHex) const { // Resolve UUID hex to display name ("" if unknown)
        auto it = m_uuidToName.find(uuidHex);
        return (it != m_uuidToName.end()) ? it->second : std::string{};
    }

private:
    bool ensureConnected() const;
    bool loadIdentity(const std::string& dataDir);

private:
    Connection& m_conn;
    std::array<uint8_t, 16> m_clientId{};
    std::string m_name;
    std::vector<uint8_t> m_pubKey;
    IdentityManager m_identity;
    KeyManager m_keys;
    // ===== Cached mappings =====
    std::unordered_map<std::string, std::string> m_uuidToName; // UUID hex to user name
};
