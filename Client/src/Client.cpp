#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "Protocol.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>  // memset
#include <array>
#include <vector>

bool Client::doRegister(const std::string& name, const std::vector<uint8_t>& pubKey) {
    if (pubKey.size() != 160) {
        std::cerr << "Public key must be 160 bytes\n";
        return false;
    }

    m_name = name;
    m_pubKey = pubKey;

    // Payload: NameLen(1) | Name | PublicKey(160)
    std::vector<uint8_t> payload;
    if (name.size() > 255) {
        std::cerr << "Name too long\n";
        return false;
    }

    payload.push_back(static_cast<uint8_t>(name.size()));
    payload.insert(payload.end(), name.begin(), name.end());
    payload.insert(payload.end(), pubKey.begin(), pubKey.end());

    // Header
    RequestHeader hdr{};
    std::memset(hdr.clientID, 0, 16);
    hdr.version = VERSION;
    hdr.code = static_cast<uint16_t>(RequestCode::REGISTER);
    hdr.payloadSize = static_cast<uint32_t>(payload.size());

    if (!m_conn.sendAll(reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr))) return false;
    if (!m_conn.sendAll(payload.data(), payload.size())) return false;

    // Response
    ResponseHeader rh{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&rh), sizeof(rh))) return false;
    if (rh.version != VERSION ||
        rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != 16)
    {
        std::cerr << "Invalid registration response\n";
        return false;
    }

    std::array<uint8_t, 16> id{};
    if (!m_conn.recvAll(id.data(), id.size())) return false;

    m_clientId = id;
    return Utils::saveMeInfo(m_name, m_clientId, m_pubKey);
}

std::vector<std::pair<std::array<uint8_t, 16>, std::string>> Client::requestClientsList() {
    using namespace Protocol;
    std::vector<std::pair<std::array<uint8_t, 16>, std::string>> clients;

    // --- Build header ---
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = Protocol::toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = Protocol::toLittleEndian32(0);

    // --- Send header only (no payload) ---
    if (!m_conn.sendAll(reinterpret_cast<uint8_t*>(&header), sizeof(header))) {
        std::cerr << "Failed to send request.\n";
        return clients;
    }

    // --- Receive response header ---
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return clients;

    uint16_t code = Protocol::fromLittleEndian16(resp.code);
    uint32_t size = Protocol::fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return clients;
    }
    if (code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) {
        std::cerr << "Unexpected response code.\n";
        return clients;
    }

    // --- Receive payload ---
    std::vector<uint8_t> payload(size);
    if (!m_conn.recvAll(payload.data(), size))
        return clients;

    // --- Parse payload ---
    if (size < 2) return clients;
    uint16_t count = (payload[0] | (payload[1] << 8));
    size_t offset = 2;

    for (uint16_t i = 0; i < count && offset + 17 <= size; ++i) {
        std::array<uint8_t, 16> uuid{};
        memcpy(uuid.data(), payload.data() + offset, 16);
        offset += 16;

        uint8_t nameLen = payload[offset++];
        if (offset + nameLen > size) break;

        std::string name(reinterpret_cast<char*>(payload.data() + offset), nameLen);
        offset += nameLen;

        clients.emplace_back(uuid, name);
    }

    return clients;
}


// ===============================
// Request Public Key (602 → 2102)
// ===============================
std::vector<uint8_t> Client::requestPublicKey(const std::string& targetUUID) {
    using namespace Protocol;

    if (targetUUID.size() != 16) {
        std::cerr << "Invalid UUID length.\n";
        return {};
    }

    // --- Build header ---
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = Protocol::toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    header.payloadSize = Protocol::toLittleEndian32(16);

    // --- Build buffer (header + target UUID) ---
    std::vector<uint8_t> buffer(sizeof(header) + 16);
    memcpy(buffer.data(), &header, sizeof(header));
    memcpy(buffer.data() + sizeof(header), targetUUID.data(), 16);

    // --- Send ---
    if (!m_conn.sendAll(buffer.data(), buffer.size())) {
        std::cerr << "Failed to send request.\n";
        return {};
    }

    // --- Receive response header ---
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return {};


    uint16_t code = Protocol::fromLittleEndian16(resp.code);
    uint32_t size = Protocol::fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return {};
    }
    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) || size != 160) {
        std::cerr << "Unexpected response.\n";
        return {};
    }

    // --- Receive public key payload ---
    std::vector<uint8_t> pubKey(size);
    if (!m_conn.recvAll(pubKey.data(), size)) {
        return {};
    }

    return pubKey;
}
