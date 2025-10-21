#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "Protocol.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <filesystem>

static const bool VERBOSE = true;
#define LOG(x) if (VERBOSE) { std::cout << x << std::endl; }

// ==========================================================
// Internal helper functions
// Placed in an anonymous namespace -> file-local scope
// ==========================================================
namespace {

    /// Generate or reuse a symmetric AES-128 key for a given peer.
    /// If not cached, generates a new key, stores it in KeyManager, and returns it.
    std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>
        prepareSymmetricKey(KeyManager& keys, const std::string& peerHex) {
        if (keys.hasSymmetricKey(peerHex))
            return keys.getSymmetricKey(peerHex);

        unsigned char rawKey[AESWrapper::DEFAULT_KEYLENGTH]{};
        AESWrapper::GenerateKey(rawKey, AESWrapper::DEFAULT_KEYLENGTH);

        std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> key{};
        std::memcpy(key.data(), rawKey, AESWrapper::DEFAULT_KEYLENGTH);
        LOG("[KeyManager] Generating new AES-128 key for " + peerHex.substr(0, 8));
        keys.cacheSymmetricKey(peerHex, key);
        LOG("[KeyManager] Cached AES key in memory for " + peerHex.substr(0, 8));
        return key;
    }

    /// Encrypt an AES symmetric key using the recipient's RSA public key.
    /// Returns the encrypted key as a byte vector ready for network sending.
    std::vector<uint8_t>
        encryptSymmetricKeyRSA(const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key,
            const std::vector<uint8_t>& pubKey) {
        RSAPublicWrapper rsa(reinterpret_cast<const char*>(pubKey.data()),
            static_cast<unsigned int>(pubKey.size()));
        std::string enc = rsa.encrypt(reinterpret_cast<const char*>(key.data()),
            AESWrapper::DEFAULT_KEYLENGTH);
        return std::vector<uint8_t>(enc.begin(), enc.end());
    }

    /// Encrypt a plaintext message using AES-128 with the provided symmetric key.
    /// Used for type=TEXT messages.
    std::vector<uint8_t>
        encryptTextAES(const std::vector<uint8_t>& content,
            const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key) {
        AESWrapper aes(key.data(), AESWrapper::DEFAULT_KEYLENGTH);
        std::string cipher = aes.encrypt(reinterpret_cast<const char*>(content.data()),
            static_cast<unsigned int>(content.size()));
        return std::vector<uint8_t>(cipher.begin(), cipher.end());
    }

    /// Send a ready-built packet to the server and verify a MESSAGE_RECEIVED response.
    /// Returns true if transmission succeeded and response code matches.
    bool sendMessagePacket(Connection& conn, const std::vector<uint8_t>& packet) {
        if (!conn.sendAll(packet.data(), packet.size())) return false;

        ResponseHeader resp{};
        if (!Utils::recvResponseHeader(conn, resp)) return false;

        return (Protocol::fromLittleEndian16(resp.code) ==
            static_cast<uint16_t>(ResponseCode::MESSAGE_RECEIVED));
    }

    /// Decrypts a symmetric AES key from a SEND_SYM message using the client's RSA private key.
    /// Returns a user-readable text and caches the AES key in KeyManager.
    std::string decryptSymmetricKeyRSA(const PendingMessage& msg,
        IdentityManager& identity,
        KeyManager& keys,
        const std::string& senderHex)
    {
        const std::string& privKey = identity.getPrivateKey();
        if (privKey.empty())
            return "(No private key loaded)";

        RSAPrivateWrapper rsa(privKey);
        std::string plain = rsa.decrypt(reinterpret_cast<const char*>(msg.content.data()),
            static_cast<unsigned int>(msg.content.size()));

        if (plain.size() != AESWrapper::DEFAULT_KEYLENGTH)
            return "(Invalid AES key size)";

        std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH> key{};
        std::memcpy(key.data(), plain.data(), AESWrapper::DEFAULT_KEYLENGTH);
        keys.cacheSymmetricKey(senderHex, key);

        LOG("[KeyManager] Cached AES key in memory for " + senderHex.substr(0, 8));
        return "[AES key cached in memory]";
    }

    /// Decrypts a TEXT message using the cached AES key.
    /// Returns the plaintext or an explanatory message if missing.
    std::string decryptTextAES(const PendingMessage& msg,
        KeyManager& keys,
        const std::string& senderHex)
    {
        if (!keys.hasSymmetricKey(senderHex))
            return "(No AES key in memory for sender)";

        auto key = keys.getSymmetricKey(senderHex);
        AESWrapper aes(key.data(), AESWrapper::DEFAULT_KEYLENGTH);
        return aes.decrypt(reinterpret_cast<const char*>(msg.content.data()),
            static_cast<unsigned int>(msg.content.size()));
    }

    /// Returns a short readable description for REQUEST_SYM messages.
    std::string decodeRequestSym()
    {
        return "[Request for symmetric key]";
    }
    
    /// Decode a batch of pending messages using the client's managers.
    std::vector<DecodedMessage>
        decodeMessages(const std::vector<PendingMessage>& msgs,
            IdentityManager& identity,
            KeyManager& keys) {
        std::vector<DecodedMessage> results;
        if (msgs.empty()) return results;

        for (const auto& msg : msgs) {
            DecodedMessage out{
                Utils::uuidToHex(msg.fromId),
                static_cast<MessageType>(msg.type),
                ""
            };

            try {
                switch (out.type) {
                case MessageType::SEND_SYM:
                    out.text = decryptSymmetricKeyRSA(msg, identity, keys, out.fromHex);
                    break;
                case MessageType::TEXT:
                    out.text = decryptTextAES(msg, keys, out.fromHex);
                    break;
                case MessageType::REQUEST_SYM:
                    out.text = decodeRequestSym();
                    break;
                default:
                    out.text = "(Unknown message type)";
                    break;
                }
            }
            catch (...) {
                out.text = "(Decryption failed)";
            }

            results.push_back(std::move(out));
        }
        return results;
    }

} // namespace

// ===============================
// Constructor
// ===============================
Client::Client(Connection& conn, const std::string& name, const std::string& dataDir)
    : m_conn(conn), m_name(name)
{
    if (!loadIdentity(dataDir)) {
        std::fill(m_clientId.begin(), m_clientId.end(), 0);
        LOG("[Client] No existing identity found in " + dataDir);
    }
}

// ===============================
// Helpers
// ===============================
bool Client::loadIdentity(const std::string& dataDir)
{
    if (m_identity.load(dataDir, m_name, m_clientId)) {
        LOG("[Client] Loaded identity \"" + m_name + "\" from " + dataDir + "/me.info");
        return true;
    }
    return false;
}

bool Client::ensureConnected() const
{
    std::string ip; uint16_t port;
    if (!Utils::readServerInfo(ip, port) || !m_conn.connectToServer(ip, port)) {
        std::cerr << "Failed to connect to server.\n";
        return false;
    }
    return true;
}
// ===============================
// Register (600 → 2100)
// ===============================
bool Client::doRegister(const std::string& dataDir)
{
    if (!ensureConnected()) return false;

    std::string mePath = dataDir + "/me.info";
    if (std::filesystem::exists(mePath)) {
        LOG("[" + m_name + "] Already registered, using " + mePath);
        return true;
    }

    std::filesystem::create_directories(dataDir);
    LOG("[" + m_name + "] Generating RSA key pair...");
    RSAPrivateWrapper rsa;

    const std::string privStr = rsa.getPrivateKey();
    const std::string pubStr = rsa.getPublicKey();
    std::vector<uint8_t> pubKeyDER(pubStr.begin(), pubStr.end());
    pubKeyDER.resize(PUBKEY_SIZE, 0);

    // ===== Validate and build payload =====
    if (m_name.size() > NAME_SIZE) {
        std::cerr << "Error: name too long\n";
        return false;
    }

    std::vector<uint8_t> payload(NAME_SIZE + PUBKEY_SIZE, 0);
    std::memcpy(payload.data(), m_name.c_str(), std::min(m_name.size() + 1, (size_t)NAME_SIZE));
    std::memcpy(payload.data() + NAME_SIZE, pubKeyDER.data(), PUBKEY_SIZE);

    // ===== Send header & payload =====
    RequestHeader hdr{};
    std::memset(hdr.clientID, 0, UUID_SIZE);
    hdr.version = VERSION;
    hdr.code = static_cast<uint16_t>(RequestCode::REGISTER);
    hdr.payloadSize = static_cast<uint32_t>(payload.size());

    if (!Utils::sendRequestHeader(m_conn, hdr) || !Utils::sendPayload(m_conn, payload))
        return false;

    // ===== Receive response =====
    ResponseHeader rh{};
    if (!Utils::recvResponseHeader(m_conn, rh) ||
        rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != UUID_SIZE)
    {
        std::cerr << "Invalid registration response\n";
        return false;
    }

    std::vector<uint8_t> payloadOut;
    if (!Utils::recvPayload(m_conn, payloadOut, UUID_SIZE)) return false;
    std::memcpy(m_clientId.data(), payloadOut.data(), UUID_SIZE);

    if (!m_identity.save(dataDir, m_name, m_clientId, privStr)) {
        std::cerr << "Failed to save me.info\n";
        return false;
    }

    LOG("[" + m_name + "] Registration complete. UUID saved to " + mePath);
    return true;
}

// ===============================
// Clients list (601 → 2101)
// ===============================
std::vector<std::pair<std::array<uint8_t, UUID_SIZE>, std::string>>
Client::requestClientsList() const
{
    using namespace Protocol;
    std::vector<std::pair<std::array<uint8_t, UUID_SIZE>, std::string>> clients;

    if (!ensureConnected()) return clients;

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = toLittleEndian32(0);

    if (!Utils::sendRequestHeader(m_conn, header)) return clients;

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return clients;

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t size = fromLittleEndian32(resp.payloadSize);
    if (code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST)) return clients;

    std::vector<uint8_t> payload;
    if (!Utils::recvPayload(m_conn, payload, size)) return clients;

    const size_t entrySize = UUID_SIZE + NAME_SIZE;
    for (size_t offset = 0; offset + entrySize <= payload.size(); offset += entrySize) {
        std::array<uint8_t, UUID_SIZE> uuid{};
        memcpy(uuid.data(), payload.data() + offset, UUID_SIZE);
        offset += UUID_SIZE;

        std::string raw(reinterpret_cast<char*>(payload.data() + offset), NAME_SIZE);
        std::string name = raw.substr(0, raw.find('\0'));
        clients.emplace_back(uuid, name);
    }

    return clients;
}

// ===============================
// Public Key (602 → 2102)
// ===============================
std::vector<uint8_t> Client::requestPublicKey(const std::string& targetUUIDHex)
{
    using namespace Protocol;

    if (m_keys.hasPublicKey(targetUUIDHex)) {
        LOG("[602] Using cached public key for " + targetUUIDHex.substr(0, 8));
        return m_keys.getPublicKey(targetUUIDHex);
    }

    if (!ensureConnected()) return {};
    LOG("[602] Requesting public key for " + targetUUIDHex.substr(0, 8));

    std::array<uint8_t, UUID_SIZE> targetUUID = Utils::hexToUUID(targetUUIDHex);

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    header.payloadSize = toLittleEndian32(UUID_SIZE);

    if (!Utils::sendRequestHeader(m_conn, header) ||
        !m_conn.sendAll(targetUUID.data(), UUID_SIZE))
        return {};

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return {};

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t size = fromLittleEndian32(resp.payloadSize);

    if (code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) ||
        size != UUID_SIZE + PUBKEY_SIZE)
        return {};

    std::vector<uint8_t> buffer;
    if (!Utils::recvPayload(m_conn, buffer, size)) return {};

    std::vector<uint8_t> pubKey(buffer.begin() + UUID_SIZE, buffer.end());
    m_keys.cachePublicKey(targetUUIDHex, pubKey);
    LOG("[602] Cached public key for " + targetUUIDHex.substr(0, 8));
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

    switch (type) {
    case MessageType::REQUEST_SYM:
        if (m_keys.hasSymmetricKey(targetHex)) {
            LOG("[603] AES key already cached, skipping REQUEST_SYM.");
            return true;
        }
        break;

    case MessageType::SEND_SYM: {
        auto key = prepareSymmetricKey(m_keys, targetHex);
        auto pubKey = m_keys.hasPublicKey(targetHex)
            ? m_keys.getPublicKey(targetHex)
            : requestPublicKey(targetHex);

        if (!ensureConnected()) {  // <--- add this
            std::cerr << "Failed to reconnect after requesting public key.\n";
            return false;
        }

        if (pubKey.size() != RSAPublicWrapper::KEYSIZE) return false;
        finalContent = encryptSymmetricKeyRSA(key, pubKey);
        break;
    }


    case MessageType::TEXT:
        if (!m_keys.hasSymmetricKey(targetHex)) {
            std::cerr << "No symmetric key in memory for this peer.\n";
            return false;
        }
        finalContent = encryptTextAES(content, m_keys.getSymmetricKey(targetHex));
        break;

    default:
        std::cerr << "Unsupported MessageType.\n";
        return false;
    }

    auto packet = Protocol::buildSendMessageRequest(
        m_clientId.data(), toClient.data(), type, finalContent);

    return sendMessagePacket(m_conn, packet);
}


// ===============================
// Waiting Messages (604 → 2104)
// ===============================
std::vector<PendingMessage> Client::requestWaitingMessages() const
{
    using namespace Protocol;
    std::vector<PendingMessage> messages;
    if (!ensureConnected()) return messages;

    RequestHeader header{};
    memcpy(header.clientID, m_clientId.data(), UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_WAITING_MESSAGES));
    header.payloadSize = toLittleEndian32(0);

    if (!Utils::sendRequestHeader(m_conn, header)) return messages;

    ResponseHeader resp{};
    if (!Utils::recvResponseHeader(m_conn, resp)) return messages;

    const uint16_t code = fromLittleEndian16(resp.code);
    const uint32_t payloadSize = fromLittleEndian32(resp.payloadSize);
    if (code != static_cast<uint16_t>(ResponseCode::WAITING_MESSAGES) || payloadSize == 0)
        return messages;

    std::vector<uint8_t> buffer;
    if (!Utils::recvPayload(m_conn, buffer, payloadSize)) return messages;

    size_t offset = 0;
    while (offset + UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE <= buffer.size()) {
        PendingMessage msg{};
        memcpy(msg.fromId.data(), &buffer[offset], UUID_SIZE);
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


std::vector<DecodedMessage> Client::fetchMessages() {
    auto msgs = requestWaitingMessages();  // 604
    if (msgs.empty()) {
        LOG("[604] No waiting messages.");
        return {};
    }
    LOG("[604] Decoding " + std::to_string(msgs.size()) + " messages...");
    return decodeMessages(msgs, m_identity, m_keys);  // file-local helper
}


