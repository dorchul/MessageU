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
#include <stdexcept>

static const bool VERBOSE = false;
#define LOG(x) if (VERBOSE) { std::cout << x << std::endl; }

// ==========================================================
// Internal helper functions (file-local)
// ==========================================================
namespace {

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

    std::vector<uint8_t>
        encryptSymmetricKeyRSA(const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key,
            const std::vector<uint8_t>& pubKey) {
        RSAPublicWrapper rsa(reinterpret_cast<const char*>(pubKey.data()),
            static_cast<unsigned int>(pubKey.size()));
        std::string enc = rsa.encrypt(reinterpret_cast<const char*>(key.data()),
            AESWrapper::DEFAULT_KEYLENGTH);
        return std::vector<uint8_t>(enc.begin(), enc.end());
    }

    std::vector<uint8_t>
        encryptTextAES(const std::vector<uint8_t>& content,
            const std::array<uint8_t, AESWrapper::DEFAULT_KEYLENGTH>& key) {
        AESWrapper aes(key.data(), AESWrapper::DEFAULT_KEYLENGTH);
        std::string cipher = aes.encrypt(reinterpret_cast<const char*>(content.data()),
            static_cast<unsigned int>(content.size()));
        return std::vector<uint8_t>(cipher.begin(), cipher.end());
    }

    bool sendMessagePacket(Connection& conn, const std::vector<uint8_t>& packet) {
        conn.sendAll(packet.data(), packet.size());

        ResponseHeader resp{};
        Utils::recvResponseHeader(conn, resp);

        if (resp.code != static_cast<uint16_t>(ResponseCode::MESSAGE_RECEIVED))
            throw std::runtime_error("Server did not acknowledge message (2103 expected)");

        if (resp.payloadSize != UUID_SIZE + MSG_ID_SIZE)
            throw std::runtime_error("Invalid payload size in MESSAGE_RECEIVED");

        std::vector<uint8_t> ack(resp.payloadSize);
        Utils::recvPayload(conn, ack, resp.payloadSize);  // read 20 bytes safely

        return true;
    }

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
        return "[Symmetric key recieved]";
    }

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

    std::string decodeRequestSym() {
        return "[Request for symmetric key]";
    }

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

} // anonymous namespace

void Client::cacheClientDirectory(
    const std::vector<std::pair<std::array<uint8_t, 16>, std::string>>& list)
{
    for (const auto& [uuidArr, name] : list) {
        std::string hex = Utils::uuidToHex(uuidArr);
        m_uuidToName[hex] = name;
    }
}

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

// ===============================
// ensureConnected
// ===============================
bool Client::ensureConnected() const
{
    std::string ip; uint16_t port;
    Utils::readServerInfo(ip, port);

    // Reconnect every time (server is stateless)
    m_conn.connectToServer(ip, port); // throws on failure
    return true;
}


// ===============================
// Register (600 → 2100)
// ===============================
bool Client::doRegister(const std::string& dataDir)
{
    ensureConnected(); // reconnect each time (server is stateless)

    const std::string mePath = dataDir + "/me.info";
    if (std::filesystem::exists(mePath)) {
        LOG("[" + m_name + "] Already registered, using " + mePath);
        return false;
    }

    std::filesystem::create_directories(dataDir);
    LOG("[" + m_name + "] Generating RSA key pair...");
    RSAPrivateWrapper rsa;

    const std::string privStr = rsa.getPrivateKey();
    const std::string pubStr = rsa.getPublicKey();
    std::vector<uint8_t> pubKeyDER(pubStr.begin(), pubStr.end());
    pubKeyDER.resize(PUBKEY_SIZE, 0);

    // Build & send register request
    auto packet = Protocol::buildRegisterRequest(m_name, pubKeyDER);
    m_conn.sendAll(packet.data(), packet.size()); // send via persistent connection

    // Receive response
    ResponseHeader rh{};
    Utils::recvResponseHeader(m_conn, rh);
    if (rh.code != static_cast<uint16_t>(ResponseCode::REGISTRATION_OK) ||
        rh.payloadSize != UUID_SIZE)
    {
        throw std::runtime_error("Invalid registration response");
    }

    std::vector<uint8_t> payloadOut;
    Utils::recvPayload(m_conn, payloadOut, UUID_SIZE);
    std::memcpy(m_clientId.data(), payloadOut.data(), UUID_SIZE);

    if (!m_identity.save(dataDir, m_name, m_clientId, privStr))
        throw std::runtime_error("Failed to save me.info");

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

    ensureConnected(); // reconnect each time (server is stateless)

    auto packet = Protocol::buildClientListRequest(m_clientId.data());
    m_conn.sendAll(packet.data(), packet.size()); // use persistent connection

    ResponseHeader resp{};
    Utils::recvResponseHeader(m_conn, resp); // host-endian

    if (resp.code != static_cast<uint16_t>(ResponseCode::CLIENTS_LIST))
        throw std::runtime_error("Unexpected response to 601 (expected 2101)");

    // Validate payload size and cap to prevent DoS
    const size_t entrySize = UUID_SIZE + NAME_SIZE;
    
    if (resp.payloadSize % entrySize != 0)
        throw std::runtime_error("Malformed CLIENTS_LIST payload size");
    
    if (resp.payloadSize > MAX_DIRECTORY_BYTES)
        throw std::runtime_error("CLIENTS_LIST payload too large");
    
    const size_t count = resp.payloadSize / entrySize;
    
    if (count > MAX_CLIENTS_COUNT)
        throw std::runtime_error("CLIENTS_LIST contains too many entries");
    
    std::vector<uint8_t> payload;
    Utils::recvPayload(m_conn, payload, resp.payloadSize);

    for (size_t offset = 0; offset + entrySize <= payload.size(); offset += entrySize) {
        size_t idx = offset;

        std::array<uint8_t, UUID_SIZE> uuid{};
        std::memcpy(uuid.data(), payload.data() + idx, UUID_SIZE);
        idx += UUID_SIZE;

        std::string raw(reinterpret_cast<char*>(payload.data() + idx), NAME_SIZE);
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

    ensureConnected();
    LOG("[602] Requesting public key for " + targetUUIDHex.substr(0, 8));

    const auto targetUUID = Utils::hexToUUID(targetUUIDHex);
    auto packet = Protocol::buildGetPublicKeyRequest(m_clientId.data(), targetUUID);
    m_conn.sendAll(packet.data(), packet.size());

    ResponseHeader resp{};
    Utils::recvResponseHeader(m_conn, resp);

    if (resp.code != static_cast<uint16_t>(ResponseCode::PUBLIC_KEY) ||
        resp.payloadSize != UUID_SIZE + PUBKEY_SIZE)
        throw std::runtime_error("Unexpected response (expected 2102 with fixed size)");

    std::vector<uint8_t> buffer;
    Utils::recvPayload(m_conn, buffer, resp.payloadSize);

    if (buffer.size() != UUID_SIZE + PUBKEY_SIZE)
        throw std::runtime_error("Malformed PUBLIC_KEY payload");

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

        // fetch or request the public key first
        auto pubKey = m_keys.hasPublicKey(targetHex)
            ? m_keys.getPublicKey(targetHex)
            : requestPublicKey(targetHex);  // may reconnect internally but we don't care yet

        if (pubKey.size() != RSAPublicWrapper::KEYSIZE)
            throw std::runtime_error("Invalid RSA public key size for SEND_SYM");

        finalContent = encryptSymmetricKeyRSA(key, pubKey);
        break;
    }

    case MessageType::TEXT:
        if (!m_keys.hasSymmetricKey(targetHex)) {
            LOG("[603] Aborted TEXT send – missing symmetric key.");
            return false;
        }

        if (content.size() > MAX_MESSAGE_BYTES) {
            LOG("[603] Aborted TEXT send – message too large.");
            return false;
        }
        finalContent = encryptTextAES(content, m_keys.getSymmetricKey(targetHex));
        break;

    default:
        throw std::runtime_error("Unsupported MessageType");
    }

    // connect only once, *after* possible 602 sub-request
    ensureConnected();

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

    ensureConnected(); // reconnect each time (server closes after response)

    auto packet = Protocol::buildGetWaitingMessagesRequest(m_clientId.data());
    m_conn.sendAll(packet.data(), packet.size()); // use persistent connection

    ResponseHeader resp{};
    Utils::recvResponseHeader(m_conn, resp); // host-endian

    if (resp.code != static_cast<uint16_t>(ResponseCode::WAITING_MESSAGES))
        throw std::runtime_error("Unexpected response to 604 (expected 2104)");

    if (resp.payloadSize == 0)
        return messages; // no messages is fine

    // cap total buffer size to prevent oversized pulls
    if (resp.payloadSize > MAX_DIRECTORY_BYTES)
        throw std::runtime_error("WAITING_MESSAGES payload too large");
    
    std::vector<uint8_t> buffer;
    Utils::recvPayload(m_conn, buffer, resp.payloadSize);

    size_t offset = 0;
    // bounds checks + memcpy for LE32
    while (true) {
        // need at least fixed header part per message
        if (offset + UUID_SIZE + MSG_ID_SIZE + MSG_TYPE_SIZE + CONTENT_SIZE > buffer.size())
            break;

        PendingMessage msg{};
        std::memcpy(msg.fromId.data(), &buffer[offset], UUID_SIZE);
        offset += UUID_SIZE;

        uint32_t idLE = 0;                            
        std::memcpy(&idLE, &buffer[offset], sizeof(idLE));  
        msg.id = Protocol::fromLittleEndian32(idLE);         
        offset += MSG_ID_SIZE;

        msg.type = buffer[offset++];

        uint32_t sizeLE = 0;                                   
        std::memcpy(&sizeLE, &buffer[offset], sizeof(sizeLE)); 
        uint32_t msgSize = Protocol::fromLittleEndian32(sizeLE); 
        offset += CONTENT_SIZE;

        // validate per-message size
        if (msgSize > MAX_MESSAGE_BYTES)
            throw std::runtime_error("A single waiting message exceeds allowed size");
        if (offset + msgSize > buffer.size())
            break;

        msg.content.assign(buffer.begin() + offset, buffer.begin() + offset + msgSize);
        offset += msgSize;

        messages.push_back(std::move(msg));
    }

    return messages;
}




std::vector<DecodedMessage> Client::fetchMessages() {
    auto msgs = requestWaitingMessages();  // may throw
    if (msgs.empty()) {
        LOG("[604] No waiting messages.");
        return {};
    }
    LOG("[604] Decoding " + std::to_string(msgs.size()) + " messages...");
    return decodeMessages(msgs, m_identity, m_keys);
}
