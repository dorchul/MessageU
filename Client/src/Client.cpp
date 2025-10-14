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

    // שמירת הנתונים בזיכרון
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

bool Client::requestClientsList() {
    if (!m_conn.isConnected()) {
        std::cerr << "Not connected to server.\n";
        return false;
    }

    // === Build request packet ===
    auto packet = Protocol::buildClientListRequest(m_clientId.data());

    // === Send request ===
    if (!m_conn.sendAll(packet.data(), static_cast<uint32_t>(packet.size()))) {
        std::cerr << "Failed to send clients list request.\n";
        return false;
    }

    // === Receive response header ===
    ResponseHeader resHeader{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resHeader), sizeof(resHeader))) {
        std::cerr << "Failed to receive response header.\n";
        return false;
    }

    const uint16_t code = Protocol::fromLittleEndian16(resHeader.code);
    const uint32_t payloadSize = Protocol::fromLittleEndian32(resHeader.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) {
        std::vector<uint8_t> payload(payloadSize);
        if (payloadSize > 0 && !m_conn.recvAll(payload.data(), payloadSize)) {
            std::cerr << "Failed to receive clients list payload.\n";
            return false;
        }
        std::cout << "Received clients list (" << payloadSize << " bytes)\n";
        // TODO: parse payload once server format is finalized
        return true;
    }

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cerr << "Server responded with an error.\n";
        return false;
    }

    std::cerr << "Unexpected response code: " << code << "\n";
    return false;
}

