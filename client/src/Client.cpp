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


static const bool VERBOSE = false;

// ===============================
// Register (600 → 2100)
// ===============================
bool Client::doRegister(const std::string& name, const std::string& dataDir)
{
    std::filesystem::create_directories(dataDir);
    std::string mePath = dataDir + "/me.info";

    // If already registered, just load and skip
    if (std::filesystem::exists(mePath)) {
        if (VERBOSE) std::cout << "[" << name << "] Already registered, using " << mePath << "\n";
        return true;
    }

    if (VERBOSE) std::cout << "[" << name << "] Generating RSA key pair...\n";
    RSAPrivateWrapper rsa;

    std::string privStr = rsa.getPrivateKey();
    std::string pubStr = rsa.getPublicKey();

    std::vector<uint8_t> privKeyDER(privStr.begin(), privStr.end());
    std::vector<uint8_t> pubKeyDER(pubStr.begin(), pubStr.end());

    if (pubKeyDER.size() != 160) {
        if (VERBOSE) std::cerr << "Warning: public key size = " << pubKeyDER.size()
            << " (expected 160)\n";
        pubKeyDER.resize(160, 0);
    }

    if (name.size() > 255) {
        if (VERBOSE) std::cerr << "Error: name too long\n";
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
    if (VERBOSE) std::cout << "[" << name << "] sending register request...\n";
    if (!m_conn.sendAll(payload.data(), payload.size())) return false;
    if (VERBOSE)std::cout << "[" << name << "] waiting for server response...\n";

    // Receive response header
    ResponseHeader rh{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&rh), sizeof(rh))) return false;

    if (rh.version != VERSION ||
        rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != 16)
    {
        if (VERBOSE) std::cerr << "Invalid registration response (code=" << rh.code
            << ", size=" << rh.payloadSize << ")\n";
        return false;
    }

    // Receive UUID
    std::array<uint8_t, 16> id{};
    if (!m_conn.recvAll(id.data(), id.size())) return false;
    m_clientId = id;

    // Save identity
    if (!Utils::saveMeInfo(name, m_clientId, privKeyDER, dataDir)) {
        if (VERBOSE) std::cerr << "Failed to save me.info\n";
        return false;
    }

    if (VERBOSE) std::cout << "[" << name << "] Registration complete. UUID saved.\n";
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
        if (VERBOSE) std::cerr << "Failed to send request.\n";
        return clients;
    }

    // ===== Receive response header =====
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return clients;

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        if (VERBOSE) std::cout << "Server responded with an error.\n";
        return clients;
    }
    if (code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) {
        if (VERBOSE) std::cerr << "Unexpected response code: " << code << "\n";
        return clients;
    }

    // ===== Receive full payload =====
    std::vector<uint8_t> payload(size);
    if (!m_conn.recvAll(payload.data(), size))
        return clients;

    const size_t entrySize = 16 + 255;
    if (size % entrySize != 0) {
        if (VERBOSE) std::cerr << "Invalid clients list size.\n";
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
        if (VERBOSE) std::cerr << "Invalid UUID hex length.\n";
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
        if (VERBOSE) std::cerr << "Failed to send header.\n";
        return {};
    }
    if (!m_conn.sendAll(targetUUID.data(), 16)) {
        if (VERBOSE) std::cerr << "Failed to send payload.\n";
        return {};
    }

    // Receive response
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return {};

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        if (VERBOSE) std::cout << "Server responded with an error.\n";
        return {};
    }
    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) || size != 176) {
        if (VERBOSE) std::cerr << "Unexpected response (" << code << ", size=" << size << ").\n";
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
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

// ==========================
// Send Message (603 → 2103)
// Handles type 1–2–3 with real crypto
// ==========================
bool Client::sendMessage(const std::array<uint8_t, 16>& toClient,
    MessageType type,
    const std::vector<uint8_t>& content)
{
    using namespace Protocol;

    auto uuidToHex = [](const std::array<uint8_t, 16>& id) {
        std::ostringstream oss;
        for (auto b : id) oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return oss.str();
    };

    std::vector<uint8_t> finalContent;

    if (type == MessageType::REQUEST_SYM) {
        if (VERBOSE) std::cout << "[603/Type 1] Requesting symmetric key...\n";
        // Content empty
    }
    else if (type == MessageType::SEND_SYM) {
        if (VERBOSE) std::cout << "[603/Type 2] Generating AES-128 key and encrypting with recipient RSA...\n";

        // 1) Generate AES key (16 bytes)
        unsigned char rawKey[AESWrapper::DEFAULT_KEYLENGTH]{};
        AESWrapper::GenerateKey(rawKey, AESWrapper::DEFAULT_KEYLENGTH);

        // 2) Fetch recipient public key via 602
        const std::string targetHex = uuidToHex(toClient);
        std::vector<uint8_t> pubKey = requestPublicKey(targetHex);
        if (pubKey.size() != RSAPublicWrapper::KEYSIZE) {
            std::cerr << "Invalid recipient public key size (" << pubKey.size() << ").\n";
            return false;
        }

        // 3) RSA-encrypt the AES key
        RSAPublicWrapper rsa(reinterpret_cast<const char*>(pubKey.data()),
            static_cast<unsigned int>(pubKey.size()));
        std::string enc = rsa.encrypt(reinterpret_cast<const char*>(rawKey),
            AESWrapper::DEFAULT_KEYLENGTH);

        finalContent.assign(enc.begin(), enc.end());

        // 4) Persist symmetric key locally for this peer (used by Type 3)
        try {
            std::filesystem::create_directories("data/symmkeys");
            const std::string keyPath = "data/symmkeys/" + targetHex + ".bin";
            std::ofstream ofs(keyPath, std::ios::binary | std::ios::trunc);
            ofs.write(reinterpret_cast<const char*>(rawKey), AESWrapper::DEFAULT_KEYLENGTH);
            ofs.close();
            if (VERBOSE) std::cout << "[603/Type 2] Saved symmetric key to " << keyPath << "\n";
        }
        catch (...) {
            std::cerr << "Failed to save the symmetric key locally.\n";
            return false;
        }
    }
    else if (type == MessageType::TEXT) {
        if (VERBOSE) std::cout << "[603/Type 3] Encrypting plaintext with stored symmetric key...\n";

        // Load symmetric key we previously saved for this peer
        const std::string targetHex = uuidToHex(toClient);
        const std::string keyPath = "data/symmkeys/" + targetHex + ".bin";
        unsigned char rawKey[AESWrapper::DEFAULT_KEYLENGTH]{};

        std::ifstream ifs(keyPath, std::ios::binary);
        if (!ifs.good()) {
            std::cerr << "No symmetric key for this peer. Send Type 2 first. (" << keyPath << ")\n";
            return false;
        }
        ifs.read(reinterpret_cast<char*>(rawKey), AESWrapper::DEFAULT_KEYLENGTH);
        if (ifs.gcount() != AESWrapper::DEFAULT_KEYLENGTH) {
            std::cerr << "Corrupted symmetric key file.\n";
            return false;
        }

        AESWrapper aes(rawKey, AESWrapper::DEFAULT_KEYLENGTH);
        std::string cipher = aes.encrypt(reinterpret_cast<const char*>(content.data()),
            static_cast<unsigned int>(content.size()));
        finalContent.assign(cipher.begin(), cipher.end());
    }
    else {
        std::cerr << "Unsupported MessageType.\n";
        return false;
    }

    // Build and send the 603 request
    const std::vector<uint8_t> packet =
        Protocol::buildSendMessageRequest(m_clientId.data(),
            toClient.data(),
            type,
            finalContent);

    if (!m_conn.sendAll(packet.data(), packet.size())) {
        std::cerr << "Failed to send message request.\n";
        return false;
    }

    // Read response header
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp))) {
        std::cerr << "Failed to receive response header.\n";
        return false;
    }

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        if (VERBOSE) std::cout << "Server responded with an error.\n";
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
std::vector<PendingMessage> Client::requestWaitingMessages()
{
    using namespace Protocol;
    std::vector<PendingMessage> messages;

    // ===== Build and send request =====
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_WAITING_MESSAGES));
    header.payloadSize = toLittleEndian32(0);

    if (!m_conn.sendAll(reinterpret_cast<uint8_t*>(&header), sizeof(header)))
        return messages;

    // ===== Receive response header =====
    ResponseHeader resp{};
    if (!m_conn.recvAll(reinterpret_cast<uint8_t*>(&resp), sizeof(resp)))
        return messages;

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);

    if (code != static_cast<uint16_t>(ResponseCode::WAITING_MESSAGES) || payloadSize == 0)
        return messages;

    // ===== Read payload =====
    std::vector<uint8_t> buffer(payloadSize);
    if (!m_conn.recvAll(buffer.data(), payloadSize))
        return messages;

    // ===== Parse sequential messages =====
    size_t offset = 0;
    while (offset + 25 <= buffer.size()) {
        PendingMessage msg{};
        memcpy(msg.fromId.data(), &buffer[offset], 16);
        offset += 16;

        msg.id = fromLittleEndian32(*reinterpret_cast<uint32_t*>(&buffer[offset]));
        offset += 4;

        msg.type = buffer[offset++];
        uint32_t msgSize = fromLittleEndian32(*reinterpret_cast<uint32_t*>(&buffer[offset]));
        offset += 4;

        if (offset + msgSize > buffer.size()) break;
        msg.content.assign(buffer.begin() + offset, buffer.begin() + offset + msgSize);
        offset += msgSize;

        messages.push_back(std::move(msg));
    }

    return messages;
}


