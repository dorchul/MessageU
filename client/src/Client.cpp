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

static const bool VERBOSE = true;
#define LOG(x) if (VERBOSE) { std::cout << x << std::endl; }

// ===============================
// Register (600 → 2100)
// ===============================
bool Client::doRegister(const std::string & name, const std::string & dataDir)
{
    if (!ensureConnected()) return false;

    std::string userDir = dataDir + "/" + name;
    std::string mePath = userDir + "/me.info";

    // If already registered, skip
    if (std::filesystem::exists(mePath)) {
        LOG("[" + name + "] Already registered, using " + mePath);
        return true;
    }

    // Create folder only if not registered
    std::filesystem::create_directories(userDir);
    LOG("[" + name + "] Using user data directory: " + userDir);


    LOG("[" + name + "] Generating RSA key pair...");
    RSAPrivateWrapper rsa;

    std::string privStr = rsa.getPrivateKey();
    std::string pubStr = rsa.getPublicKey();

    std::vector<uint8_t> privKeyDER(privStr.begin(), privStr.end());
    std::vector<uint8_t> pubKeyDER(pubStr.begin(), pubStr.end());

    if (pubKeyDER.size() != PUBKEY_SIZE) {
        std::cerr << "Warning: public key size = " << pubKeyDER.size() << " (expected 160)\n";
        pubKeyDER.resize(PUBKEY_SIZE, 0);
    }

    if (name.size() > NAME_SIZE) {
        std::cerr << "Error: name too long\n";
        return false;
    }

    // Ensure name contains only ASCII printable characters (0x20–0x7E)
    for (unsigned char c : name) {
        if (c < 0x20 || c > 0x7E) {
            std::cerr << "Error: name must contain only ASCII printable characters\n";
            return false;
        }
    }
    // Payload: Name (255B) + PublicKey (160B)
    std::vector<uint8_t> payload(NAME_SIZE + PUBKEY_SIZE, 0);
    std::memcpy(payload.data(), name.c_str(), std::min<size_t>(name.size() + 1, NAME_SIZE));
    std::memcpy(payload.data() + NAME_SIZE, pubKeyDER.data(), PUBKEY_SIZE);

    // Header
    RequestHeader hdr{};
    std::memset(hdr.clientID, 0, UUID_SIZE);
    hdr.version = VERSION;
    hdr.code = static_cast<uint16_t>(RequestCode::REGISTER);
    hdr.payloadSize = static_cast<uint32_t>(payload.size());

    // Send request
    if (!Utils::sendRequestHeader(m_conn, hdr)) return false;
    LOG("[" + name + "] Sending register request...");
    if (!Utils::sendPayload(m_conn, payload)) return false;
    LOG("[" + name + "] Waiting for server response...");

    // Receive response header
    ResponseHeader rh{};
    if (!Utils::recvResponseHeader(m_conn, rh)) return false;

    if (rh.version != VERSION ||
        rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != UUID_SIZE)
    {
        std::cerr << "Invalid registration response (code=" << rh.code
            << ", size=" << rh.payloadSize << ")\n";
        return false;
    }

    // Receive UUID
    std::array<uint8_t, UUID_SIZE> id{};
    std::vector<uint8_t> payloadOut;
    if (!Utils::recvPayload(m_conn, payloadOut, UUID_SIZE)) return false;
    std::memcpy(id.data(), payloadOut.data(), UUID_SIZE);
    m_clientId = id;

    // Save identity
    if (!Utils::saveMeInfo(name, m_clientId, privKeyDER, userDir)) {
        std::cerr << "Failed to save me.info\n";
        return false;
    }

    LOG("[" + name + "] Registration complete. UUID saved to " + mePath);
    m_name = name;
    return true;
}


// ===============================
// Clients list (601 → 2101)
// ===============================
std::vector<std::pair<std::array<uint8_t, UUID_SIZE>, std::string>> Client::requestClientsList()
{
    using namespace Protocol;
    std::vector<std::pair<std::array<uint8_t, UUID_SIZE>, std::string>> clients;
    
    if (!ensureConnected()) return clients;

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = toLittleEndian32(0);

    if (!Utils::sendRequestHeader(m_conn, header)) {
        std::cerr << "Failed to send request.\n";
        return clients;
    }

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return clients;

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        LOG("Server responded with an error.");
        return clients;
    }
    if (code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) {
        std::cerr << "Unexpected response code: " << code << "\n";
        return clients;
    }

    std::vector<uint8_t> payload;
    if (!Utils::recvPayload(m_conn, payload, size)) return clients;

    const size_t entrySize = UUID_SIZE + NAME_SIZE;
    if (size % entrySize != 0) {
        std::cerr << "Invalid clients list size.\n";
        return clients;
    }

    uint16_t count = static_cast<uint16_t>(size / entrySize);
    size_t offset = 0;

    for (uint16_t i = 0; i < count; ++i) {
        std::array<uint8_t, UUID_SIZE> uuid{};
        memcpy(uuid.data(), payload.data() + offset, UUID_SIZE);
        offset += UUID_SIZE;

        std::string rawName(reinterpret_cast<char*>(payload.data() + offset), NAME_SIZE);
        size_t nullPos = rawName.find('\0');
        std::string name = (nullPos != std::string::npos) ? rawName.substr(0, nullPos) : rawName;
        offset += NAME_SIZE;

        clients.emplace_back(uuid, name);
    }

    return clients;
}

std::vector<uint8_t> Client::requestPublicKey(const std::string& targetUUIDHex)
{
    using namespace Protocol;

    // ===== 1. Check cache first =====
    auto it = m_cachedPubKeys.find(targetUUIDHex);
    if (it != m_cachedPubKeys.end()) {
        LOG("[602] Using cached public key for " + targetUUIDHex.substr(0, 8));
        return it->second;
    }

    LOG("[602] No cached public key, requesting from server...");

    if (!ensureConnected()) return {};

    std::array<uint8_t, UUID_SIZE> targetUUID = Utils::hexToUUID(targetUUIDHex);

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    header.payloadSize = toLittleEndian32(UUID_SIZE);

    if (!Utils::sendRequestHeader(m_conn, header)) return {};
    if (!m_conn.sendAll(targetUUID.data(), UUID_SIZE)) return {};

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return {};

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        LOG("[602] Server responded with an error.");
        return {};
    }

    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) ||
        size != UUID_SIZE + PUBKEY_SIZE) {
        std::cerr << "[602] Unexpected response (" << code << ", size=" << size << ").\n";
        return {};
    }

    std::vector<uint8_t> buffer;
    if (!Utils::recvPayload(m_conn, buffer, size)) return {};

    std::vector<uint8_t> pubKey(buffer.begin() + UUID_SIZE, buffer.end());
    m_cachedPubKeys[targetUUIDHex] = pubKey;
    LOG("[602] Public key cached for " + targetUUIDHex.substr(0, 8));

    return pubKey;
}


// ===============================
// Send Message (603 → 2103)
// ===============================
bool Client::sendMessage(const std::array<uint8_t, UUID_SIZE>& toClient,
    MessageType type,
    const std::vector<uint8_t>& content)
{
    using namespace Protocol;
    
    if (!ensureConnected()) return false;

    const std::string targetHex = Utils::uuidToHex(toClient);
    std::vector<uint8_t> finalContent;

    if (type == MessageType::REQUEST_SYM) {
        LOG("[603/Type 1] Requesting symmetric key...");

        // ===== Check if we already have a symmetric key =====
        auto symIt = m_symmKeys.find(targetHex);
        if (symIt != m_symmKeys.end()) {
            LOG("[603/Type 1] Symmetric key already cached. Skipping REQUEST_SYM.");
            return true; // No need to request again
        }
    }

    else if (type == MessageType::SEND_SYM) {
        LOG("[603/Type 2] Preparing to send symmetric key...");

        std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> key{};

        // ===== If cached AES key exists, reuse it =====
        auto symIt = m_symmKeys.find(targetHex);
        if (symIt != m_symmKeys.end()) {
            key = symIt->second;
            LOG("[603/Type 2] Using cached AES key for this peer.");
        }
        else {
            LOG("[603/Type 2] Generating new AES-128 key...");
            unsigned char rawKey[AESWrapper::DEFAULT_KEYLENGTH]{};
            AESWrapper::GenerateKey(rawKey, AESWrapper::DEFAULT_KEYLENGTH);
            std::memcpy(key.data(), rawKey, AESWrapper::DEFAULT_KEYLENGTH);
            m_symmKeys[targetHex] = key;
            LOG("[603/Type 2] New AES key generated and cached.");
        }

        // ===== Retrieve recipient public key =====
        std::vector<uint8_t> pubKey;
        auto it = m_cachedPubKeys.find(targetHex);
        if (it != m_cachedPubKeys.end()) {
            pubKey = it->second;
            LOG("[603/Type 2] Using cached public key.");
        }
        else {
            LOG("[603/Type 2] No cached public key. Requesting from server...");
            pubKey = requestPublicKey(targetHex);
            if (pubKey.size() != RSAPublicWrapper::KEYSIZE) {
                std::cerr << "Invalid recipient public key size (" << pubKey.size() << ").\n";
                return false;
            }
            if (!ensureConnected()) {
                std::cerr << "Failed to reconnect after requesting public key.\n";
                return false;
            }
        }

        // ===== Encrypt AES key with recipient RSA =====
        RSAPublicWrapper rsa(reinterpret_cast<const char*>(pubKey.data()), (unsigned int)pubKey.size());
        std::string enc = rsa.encrypt(reinterpret_cast<const char*>(key.data()), AESWrapper::DEFAULT_KEYLENGTH);
        finalContent.assign(enc.begin(), enc.end());

        LOG("[603/Type 2] AES key encrypted with recipient RSA and ready to send.");
    }



    else if (type == MessageType::TEXT) {
        LOG("[603/Type 3] Encrypting plaintext with stored symmetric key...");
        auto it = m_symmKeys.find(targetHex);
        if (it == m_symmKeys.end()) {
            std::cerr << "No symmetric key in memory for this peer.\n";
            return false;
        }

        AESWrapper aes(it->second.data(), AESWrapper::DEFAULT_KEYLENGTH);
        std::string cipher = aes.encrypt(reinterpret_cast<const char*>(content.data()),
            static_cast<unsigned int>(content.size()));
        finalContent.assign(cipher.begin(), cipher.end());
    }
    else {
        std::cerr << "Unsupported MessageType.\n";
        return false;
    }

    const std::vector<uint8_t> packet =
        Protocol::buildSendMessageRequest(m_clientId.data(), toClient.data(), type, finalContent);

    if (!m_conn.sendAll(packet.data(), packet.size())) {
        std::cerr << "Failed to send message request.\n";
        return false;
    }

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return false;

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);

    if (code == static_cast<uint16_t>(ResponseCode::_ERROR_)) {
        LOG("Server responded with an error.");
        if (payloadSize > 0) {
            std::vector<uint8_t> drain;
            Utils::recvPayload(m_conn, drain, payloadSize);
        }
        return false;
    }

    if (code != static_cast<uint16_t>(ResponseCode::MESSAGE_RECEIVED)) {
        std::cerr << "Unexpected response code: " << code << "\n";
        if (payloadSize > 0) {
            std::vector<uint8_t> drain;
            Utils::recvPayload(m_conn, drain, payloadSize);
        }
        return false;
    }

    if (payloadSize > 0) {
        std::vector<uint8_t> drain;
        Utils::recvPayload(m_conn, drain, payloadSize);
    }

    return true;
}

// ===============================
// Waiting Messages (604 → 2104)
// ===============================
std::vector<PendingMessage> Client::requestWaitingMessages()
{
    using namespace Protocol;
    std::vector<PendingMessage> messages;
    
    if (!ensureConnected()) return messages;
    
    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_WAITING_MESSAGES));
    header.payloadSize = toLittleEndian32(0);

    if (!Utils::sendRequestHeader(m_conn, header)) return messages;

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return messages;

    uint16_t code = fromLittleEndian16(resp.code);
    uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);

    if (code != static_cast<uint16_t>(ResponseCode::WAITING_MESSAGES) || payloadSize == 0)
        return messages;

    std::vector<uint8_t> buffer;
    if (!Utils::recvPayload(m_conn, buffer, payloadSize)) return messages;

    size_t offset = 0;
    while (offset + UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE <= buffer.size()) {
        PendingMessage msg{};
        memcpy(msg.fromId.data(), &buffer[offset], 16);
        offset += UUID_SIZE;

        msg.id = fromLittleEndian32(*reinterpret_cast<uint32_t*>(&buffer[offset]));
        offset += MSG_ID_SIZE;

        msg.type = buffer[offset++];
        uint32_t msgSize = fromLittleEndian32(*reinterpret_cast<uint32_t*>(&buffer[offset]));
        offset += CONTENT_SIZE;

        if (offset + msgSize > buffer.size()) break;
        msg.content.assign(buffer.begin() + offset, buffer.begin() + offset + msgSize);
        offset += msgSize;

        messages.push_back(std::move(msg));
    }

    return messages;
}

// ===============================
// Decode messages
// ===============================
std::vector<DecodedMessage> Client::decodeMessages(const std::vector<PendingMessage>& msgs)
{
    std::vector<DecodedMessage> results;
    if (msgs.empty()) return results;

    for (const auto& msg : msgs) {
        DecodedMessage out;
        out.fromHex = Utils::uuidToHex(msg.fromId);
        out.type = static_cast<MessageType>(msg.type);

        try {
            if (msg.type == (uint8_t)MessageType::SEND_SYM) {
                std::string name;
                std::array<uint8_t, 16> uuid{};
                std::vector<uint8_t> priv;
                if (!Utils::loadMeInfo(name, uuid, priv, "data/" + m_name)) {
                    out.text = "(Cannot load private key)";
                    results.push_back(out);
                    continue;
                }

                RSAPrivateWrapper rsa((const char*)priv.data(), (unsigned int)priv.size());
                std::string plain = rsa.decrypt((const char*)msg.content.data(),
                    (unsigned int)msg.content.size());
                if (plain.size() != AESWrapper::DEFAULT_KEYLENGTH) {
                    out.text = "(Invalid AES key size)";
                    results.push_back(out);
                    continue;
                }

                std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> key{};
                std::memcpy(key.data(), plain.data(), AESWrapper::DEFAULT_KEYLENGTH);
                m_symmKeys[out.fromHex] = key;
                out.text = "[AES key cached in memory]";
            }
            else if (msg.type == (uint8_t)MessageType::TEXT) {
                auto it = m_symmKeys.find(out.fromHex);
                if (it == m_symmKeys.end()) {
                    out.text = "(No AES key in memory for sender)";
                    results.push_back(out);
                    continue;
                }

                AESWrapper aes(it->second.data(), AESWrapper::DEFAULT_KEYLENGTH);
                std::string plain = aes.decrypt((const char*)msg.content.data(),
                    (unsigned int)msg.content.size());
                out.text = plain;
            }
            else if (msg.type == (uint8_t)MessageType::REQUEST_SYM) {
                out.text = "[Request for symmetric key]";
            }
            else {
                out.text = "(Unknown message type)";
            }
        }
        catch (...) {
            out.text = "(Decryption failed)";
        }

        results.push_back(out);
    }

    return results;
}

bool Client::ensureConnected()
{
    std::string ip;
    uint16_t port;
    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info\n";
        return false;
    }
    if (!m_conn.connectToServer(ip, port)) {
        std::cerr << "Failed to connect to server.\n";
        return false;
    }
    return true;
}
