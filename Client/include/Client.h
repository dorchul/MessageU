#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include "Protocol.h"

class Connection;

class Client {
public:
    explicit Client(Connection& conn)
        : m_conn(conn) {}

    // REGISTER (600)
    bool doRegister(const std::string& name, const std::vector<uint8_t>& pubKey);

    // GET CLIENTS LIST (601)
    std::vector<std::pair<std::array<uint8_t, 16>, std::string>> requestClientsList();

    // GET PUBLIC KEY (602)
    std::vector<uint8_t> requestPublicKey(const std::string& targetUUID);

    // SEND MESSAGE (603)
    bool sendMessage(const std::array<uint8_t, 16>& toClient,
        MessageType type,
        const std::vector<uint8_t>& content);

    // GET WAITING MESSAGES (604)
    void requestWaitingMessages();
    
    const std::array<uint8_t, 16>& id() const { return m_clientId; }
    const std::string& name() const { return m_name; }


private:
    Connection& m_conn;
    std::array<uint8_t, 16> m_clientId{};
    std::string m_name;
    std::vector<uint8_t> m_pubKey;
};
