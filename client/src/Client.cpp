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

    // Build payload: [NameLen][Name][PubKey(160)]
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(name.size()));
    payload.insert(payload.end(), name.begin(), name.end());
    payload.insert(payload.end(), pubKeyDER.begin(), pubKeyDER.end());

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
// Clients list (601 → 2101)
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

    if (size < 2) return clients; // at least the count field

    uint16_t count = payload[0] | (payload[1] << 8);
    size_t offset = 2;

    // ===== Parse client entries =====
    const size_t entrySize = 16 + 255;
    for (uint16_t i = 0; i < count && offset + entrySize <= size; ++i) {
        std::array<uint8_t, 16> uuid{};
        memcpy(uuid.data(), payload.data() + offset, 16);
        offset += 16;

        // Extract name (255 bytes, null-terminated)
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
std::vector<uint8_t> Client::requestPublicKey(const std::string& targetUUID)
{
    using namespace Protocol;

    if (targetUUID.size() != 16) {
        std::cerr << "Invalid UUID length.\n";
        return {};
    }

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    header.payloadSize = toLittleEndian32(16);

    std::vector<uint8_t> buffer(sizeof(header) + 16);
    memcpy(buffer.data(), &header, sizeof(header));
    memcpy(buffer.data() + sizeof(header), targetUUID.data(), 16);

    if (!m_conn.sendAll(buffer.data(), buffer.size())) {
        std::cerr << "Failed to send request.\n";
        return {};
    }

    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return {};

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        std::cout << "Server responded with an error.\n";
        return {};
    }
    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) || size != 160) {
        std::cerr << "Unexpected response.\n";
        return {};
    }

    std::vector<uint8_t> pubKey(size);
    if (!m_conn.recvAll(pubKey.data(), size))
        return {};

    return pubKey;
}

// ===============================
// Send Message (603 → 2103)
// Handles type 1–2–3
// ===============================
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

// ===============================
// Get Waiting Messages (604 → 2104)
// ===============================
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
