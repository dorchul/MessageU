#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "Protocol.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <array>
#include <vector>
#include <filesystem>

// ===============================
// Register (600 → 2100)
// ===============================
bool Client::doRegister(const std::string& name, const std::string& dataDir)
{
    std::filesystem::create_directories(dataDir);
    std::string mePath = dataDir + "/me.info";

    // If already registered, just load and skip
    if (std::filesystem::exists(mePath)) {
        std::cout << "[" << name << "] Already registered, using " << mePath << "\n";
        return true;
    }

    std::cout << "[" << name << "] Generating RSA key pair...\n";
    RSAPrivateWrapper rsa;

    std::string privStr = rsa.getPrivateKey();
    std::string pubStr = rsa.getPublicKey();

    std::vector<uint8_t> privKeyDER(privStr.begin(), privStr.end());
    std::vector<uint8_t> pubKeyDER(pubStr.begin(), pubStr.end());

    if (pubKeyDER.size() != 160) {
        std::cerr << "Warning: public key size = " << pubKeyDER.size()
            << " (expected 160)\n";
        pubKeyDER.resize(160, 0);
    }

    if (name.size() > 255) {
        std::cerr << "Error: name too long\n";
        return false;
    }

    // Build payload: [Name (255 bytes, null-terminated)] + [PublicKey (160 bytes)]
    std::vector<uint8_t> payload(255 + 160, 0);
    std::memcpy(payload.data(), name.c_str(), std::min<size_t>(name.size() + 1, 255));
    std::memcpy(payload.data() + 255, pubKeyDER.data(), 160);

    // Header
    RequestHeader hdr{};
    std::memset(hdr.clientID, 0, 16);
    hdr.version = VERSION;
    hdr.code = static_cast<uint16_t>(RequestCode::REGISTER);
    hdr.payloadSize = static_cast<uint32_t>(payload.size());

    // Send
    if (!m_conn.sendAll(reinterpret_cast<const uint8_t*>(&hdr), sizeof(hdr))) return false;
    if (!m_conn.sendAll(payload.data(), payload.size())) return false;

    // Receive response header
    ResponseHeader rh{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&rh), sizeof(rh))) return false;

    if (rh.version != VERSION ||
        rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != 16)
    {
        std::cerr << "Invalid registration response (code=" << rh.code
            << ", size=" << rh.payloadSize << ")\n";
        return false;
    }

    // Receive UUID
    std::array<uint8_t, 16> id{};
    if (!m_conn.recvAll(id.data(), id.size())) return false;
    m_clientId = id;

    // Save identity
    if (!Utils::saveMeInfo(name, m_clientId, privKeyDER, dataDir)) {
        std::cerr << "Failed to save me.info\n";
        return false;
    }

    std::cout << "[" << name << "] Registration complete. UUID saved.\n";
    return true;
}



// ===============================
// Request Clients list (601 → 2101)
// ===============================
std::vector<std::pair<std::array<uint8_t, 16>, std::string>> Client::requestClientsList()
{
    using namespace Protocol;
    std::vector<std::pair<std::array<uint8_t, 16>, std::string>> clients;

    // ===== Build and send request =====
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = toLittleEndian32(0);

    if (!m_conn.sendAll(reinterpret_cast<const uint8_t*>(&header), sizeof(header))) {
        std::cerr << "Failed to send request.\n";
        return clients;
    }

    // ===== Receive response header =====
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return clients;

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return clients;
    }
    if (code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) {
        std::cerr << "Unexpected response code: " << code << "\n";
        return clients;
    }

    // ===== Receive full payload =====
    std::vector<uint8_t> payload(size);
    if (!m_conn.recvAll(payload.data(), size))
        return clients;

    const size_t entrySize = 16 + 255;
    if (size % entrySize != 0) {
        std::cerr << "Invalid clients list size.\n";
        return clients;
    }

    uint16_t count = static_cast<uint16_t>(size / entrySize);
    size_t offset = 0;

    for (uint16_t i = 0; i < count; ++i) {
        std::array<uint8_t, 16> uuid{};
        memcpy(uuid.data(), payload.data() + offset, 16);
        offset += 16;

        std::string rawName(reinterpret_cast<char*>(payload.data() + offset), 255);
        size_t nullPos = rawName.find('\0');
        std::string name = (nullPos != std::string::npos) ? rawName.substr(0, nullPos) : rawName;
        offset += 255;

        clients.emplace_back(uuid, name);
    }


    return clients;
}

// ===============================
// Request Public Key (602 → 2102)
// ===============================

std::vector<uint8_t> Client::requestPublicKey(const std::string& targetUUIDHex)
{
    using namespace Protocol;

    // Convert hex UUID → 16-byte array
    if (targetUUIDHex.size() != 32) {
        std::cerr << "Invalid UUID hex length.\n";
        return {};
    }

    std::array<uint8_t, 16> targetUUID{};
    for (size_t i = 0; i < 16; ++i) {
        std::string byteStr = targetUUIDHex.substr(i * 2, 2);
        targetUUID[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
    }

    // Build header
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    header.payloadSize = toLittleEndian32(16);

    // Send header + payload (16-byte target UUID)
    if (!m_conn.sendAll(reinterpret_cast<const uint8_t*>(&header), sizeof(header))) {
        std::cerr << "Failed to send header.\n";
        return {};
    }
    if (!m_conn.sendAll(targetUUID.data(), 16)) {
        std::cerr << "Failed to send payload.\n";
        return {};
    }

    // Receive response
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return {};

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return {};
    }
    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) || size != 176) {
        std::cerr << "Unexpected response (" << code << ", size=" << size << ").\n";
        return {};
    }

    // Receive 176 bytes (UUID + key)
    std::vector<uint8_t> buffer(size);
    if (!m_conn.recvAll(buffer.data(), size))
        return {};

    // Extract public key (last 160 bytes)
    std::vector<uint8_t> pubKey(buffer.begin() + 16, buffer.end());
    return pubKey;
}

// ==========================
// Send Message (603 → 2103)
// Handles type 1–2–3
// ==========================
bool Client::sendMessage(const std::array<uint8_t, 16>& toClient,
    MessageType type,
    const std::vector<uint8_t>& content)
{
    using namespace Protocol;

    // Encrypt AES key or message depending on type
    std::vector<uint8_t> finalContent = content;

    if (type == MessageType::REQUEST_SYM) {
        std::cout << "[Type 1] Requesting AES key from peer...\n";
        finalContent.clear();
    }
    else if (type == MessageType::SEND_SYM) {
        std::cout << "[Type 2] Sending AES key (RSA-encrypted)...\n";
    }
    else if (type == MessageType::TEXT) {
        std::cout << "[Type 3] Sending encrypted text message...\n";
    }

    const std::vector<uint8_t> packet =
        Protocol::buildSendMessageRequest(m_clientId.data(),
            toClient.data(),
            type,
            finalContent);

    if (!m_conn.sendAll(packet.data(), packet.size())) {
        std::cerr << "Failed to send message request.\n";
        return false;
    }

    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp))) {
        std::cerr << "Failed to receive response header.\n";
        return false;
    }

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        if (payloadSize > 0) {
            std::vector<uint8_t> drain(payloadSize);
            m_conn.recvAll(drain.data(), payloadSize);
        }
        return false;
    }

    if (code != static_cast<uint16_t>(ResponseCode::MESSAGE_RECEIVED)) {
        std::cerr << "Unexpected response code: " << code << "\n";
        if (payloadSize > 0) {
            std::vector<uint8_t> drain(payloadSize);
            m_conn.recvAll(drain.data(), payloadSize);
        }
        return false;
    }

    if (payloadSize > 0) {
        std::vector<uint8_t> drain(payloadSize);
        m_conn.recvAll(drain.data(), payloadSize);
    }

    return true;
}

// =====================================
// Request Waiting Messages (604 → 2104)
// =====================================
void Client::requestWaitingMessages()
{
    using namespace Protocol;

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_WAITING_MESSAGES));
    header.payloadSize = toLittleEndian32(0);

    if (!m_conn.sendAll(reinterpret_cast<uint8_t*>(&header), sizeof(header))) {
        std::cerr << "Failed to send 604 request.\n";
        return;
    }

    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp))) {
        std::cerr << "Failed to receive 2104 header.\n";
        return;
    }

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return;
    }
    if (code != static_cast<uint16_t>(ResponseCode::WAITING_MESSAGES)) {
        std::cerr << "Unexpected response code: " << code << "\n";
        return;
    }

    std::vector<uint8_t> payload(size);
    if (size > 0 && !m_conn.recvAll(payload.data(), size)) {
        std::cerr << "Failed to receive payload.\n";
        return;
    }

    size_t offset = 0;
    int msg_count = 0;
    while (offset + 21 <= payload.size()) {
        std::array<uint8_t, 16> fromUUID{};
        std::memcpy(fromUUID.data(), payload.data() + offset, 16);
        offset += 16;

        uint8_t type = payload[offset++];
        uint32_t contentSize = 0;
        std::memcpy(&contentSize, payload.data() + offset, 4);
        contentSize = fromLittleEndian32(contentSize);
        offset += 4;

        if (offset + contentSize > payload.size()) break;
        std::vector<uint8_t> content(payload.begin() + offset, payload.begin() + offset + contentSize);
        offset += contentSize;

        std::cout << "\n[Message " << ++msg_count << "] From: "
            << Utils::uuidToHex(fromUUID)
            << " | Type: " << static_cast<int>(type)
            << " | Size: " << contentSize << "\n";

        if (type == static_cast<uint8_t>(MessageType::TEXT)) {
            std::string text(content.begin(), content.end());
            std::cout << "  Text: " << text << "\n";
        }
    }

    if (msg_count == 0)
        std::cout << "No waiting messages.\n";
}
