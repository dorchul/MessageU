#include "Protocol.h"
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <array>

// ===== Safety Checks =====
static_assert(sizeof(RequestHeader) == REQ_HEADER_SIZE, "RequestHeader size mismatch");
static_assert(sizeof(ResponseHeader) == RES_HEADER_SIZE, "ResponseHeader size mismatch");

// ===== Endian Conversion =====
static bool isLittleEndian() {
    uint16_t num = 1;
    uint8_t bytes[sizeof(num)];
    std::memcpy(bytes, &num, sizeof(num));   // safer than reinterpret_cast
    return bytes[0] == 1;
}

uint16_t Protocol::toLittleEndian16(uint16_t value) {
    if (isLittleEndian()) return value;
    return (value >> 8) | (value << 8);
}

uint32_t Protocol::toLittleEndian32(uint32_t value) {
    if (isLittleEndian()) return value;
    return ((value >> 24) & 0x000000FF) |
        ((value >> 8) & 0x0000FF00) |
        ((value << 8) & 0x00FF0000) |
        ((value << 24) & 0xFF000000);
}

uint16_t Protocol::fromLittleEndian16(uint16_t value) {
    return toLittleEndian16(value);
}

uint32_t Protocol::fromLittleEndian32(uint32_t value) {
    return toLittleEndian32(value);
}

#ifdef PROTOCOL_SELFTEST
// ===== Serialization Test =====
void testHeaderSerialization() {
    RequestHeader req{};
    std::memset(req.clientID, 0xAB, UUID_SIZE);
    req.version = VERSION;
    req.code = Protocol::toLittleEndian16(static_cast<uint16_t>(RequestCode::REGISTER));
    req.payloadSize = Protocol::toLittleEndian32(128);

    // Serialize
    uint8_t buffer[sizeof(RequestHeader)];
    std::memcpy(buffer, &req, sizeof(req));

    // Deserialize
    RequestHeader parsed{};
    std::memcpy(&parsed, buffer, sizeof(parsed));

    // Verify
    std::cout << "Header size: " << sizeof(req) << " bytes\n";
    std::cout << "Version: " << (int)parsed.version << "\n";
    std::cout << "Code: " << Protocol::fromLittleEndian16(parsed.code) << "\n";
    std::cout << "PayloadSize: " << Protocol::fromLittleEndian32(parsed.payloadSize) << "\n";
}
#endif

// ===== Internal helpers =====
namespace {
    inline void ensurePayloadCap(uint32_t size) {
        if (size > MAX_PAYLOAD_SIZE)
            throw std::runtime_error("Protocol: payload exceeds MAX_PAYLOAD_SIZE");
    }

    inline void ensureMessageCap(size_t size) {
        if (size > MAX_MESSAGE_BYTES)
            throw std::runtime_error("Protocol: message exceeds MAX_MESSAGE_BYTES");
    }
}

// ===== Build "Clients List" Request (601) =====
std::vector<uint8_t> Protocol::buildClientListRequest(const uint8_t clientID[UUID_SIZE]) {
    RequestHeader header{};
    std::memcpy(header.clientID, clientID, UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = toLittleEndian32(0); // No payload

    std::vector<uint8_t> buffer(sizeof(RequestHeader));
    std::memcpy(buffer.data(), &header, sizeof(RequestHeader));
    return buffer;
}

// ===== Build "Send Message" Request (603) =====
std::vector<uint8_t> Protocol::buildSendMessageRequest(
    const uint8_t clientID[UUID_SIZE],
    const uint8_t toClientID[UUID_SIZE],
    MessageType type,
    const std::vector<uint8_t>& content)
{
    ensureMessageCap(content.size());
    // ---- Prepare payload ----
    MessagePayload payload{};
    std::memcpy(payload.toClientID, toClientID, UUID_SIZE);
    payload.type = static_cast<uint8_t>(type);
    payload.contentSize = toLittleEndian32(static_cast<uint32_t>(content.size()));

    const uint32_t payloadSize = sizeof(MessagePayload) + static_cast<uint32_t>(content.size());
    ensurePayloadCap(payloadSize);

    // ---- Build header ----
    RequestHeader header{};
    std::memcpy(header.clientID, clientID, UUID_SIZE);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::SEND_MESSAGE));
    header.payloadSize = toLittleEndian32(payloadSize);

    // ---- Serialize header + payload ----
    std::vector<uint8_t> packet;
    packet.reserve(sizeof(RequestHeader) + payloadSize);

    const uint8_t* headerPtr = reinterpret_cast<const uint8_t*>(&header);
    packet.insert(packet.end(), headerPtr, headerPtr + sizeof(RequestHeader));

    const uint8_t* payloadPtr = reinterpret_cast<const uint8_t*>(&payload);
    packet.insert(packet.end(), payloadPtr, payloadPtr + sizeof(MessagePayload));

    if (!content.empty())
        packet.insert(packet.end(), content.begin(), content.end());

    return packet;
}

// ===== Build "Register" Request (600) =====
std::vector<uint8_t> Protocol::buildRegisterRequest(
    const std::string& name,
    const std::vector<uint8_t>& pubKeyDER)
{
    if (name.size() >= NAME_SIZE)
        throw std::runtime_error("Protocol: name too long for registration");

    // --- Build payload ---
    std::vector<uint8_t> payload(NAME_SIZE + PUBKEY_SIZE, 0);
    ensurePayloadCap(static_cast<uint32_t>(payload.size()));
    std::memcpy(payload.data(), name.c_str(),
        std::min(name.size() + 1, (size_t)NAME_SIZE));
    std::memcpy(payload.data() + NAME_SIZE, pubKeyDER.data(),
        std::min(pubKeyDER.size(), (size_t)PUBKEY_SIZE));

    // --- Header ---
    RequestHeader hdr{};
    std::memset(hdr.clientID, 0, UUID_SIZE); // unregistered
    hdr.version = VERSION;
    hdr.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::REGISTER));
    hdr.payloadSize = toLittleEndian32(static_cast<uint32_t>(payload.size()));

    // --- Serialize ---
    std::vector<uint8_t> packet(sizeof(RequestHeader) + payload.size());
    std::memcpy(packet.data(), &hdr, sizeof(RequestHeader));
    std::memcpy(packet.data() + sizeof(RequestHeader), payload.data(), payload.size());
    return packet;
}

// ===== Build "Get Public Key" Request (602) =====
std::vector<uint8_t> Protocol::buildGetPublicKeyRequest(
    const uint8_t clientID[UUID_SIZE],
    const std::array<uint8_t, UUID_SIZE>& targetUUID)
{
    RequestHeader hdr{};
    std::memcpy(hdr.clientID, clientID, UUID_SIZE);
    hdr.version = VERSION;
    hdr.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_PUBLIC_KEY));
    hdr.payloadSize = toLittleEndian32(UUID_SIZE);

    ensurePayloadCap(UUID_SIZE);
    std::vector<uint8_t> packet(sizeof(RequestHeader) + UUID_SIZE);
    std::memcpy(packet.data(), &hdr, sizeof(RequestHeader));
    std::memcpy(packet.data() + sizeof(RequestHeader),
        targetUUID.data(), UUID_SIZE);
    return packet;
}

// ===== Build "Get Waiting Messages" Request (604) =====
std::vector<uint8_t> Protocol::buildGetWaitingMessagesRequest(
    const uint8_t clientID[UUID_SIZE])
{
    RequestHeader hdr{};
    std::memcpy(hdr.clientID, clientID, UUID_SIZE);
    hdr.version = VERSION;
    hdr.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_WAITING_MESSAGES));
    hdr.payloadSize = toLittleEndian32(0);

    std::vector<uint8_t> packet(sizeof(RequestHeader));
    std::memcpy(packet.data(), &hdr, sizeof(RequestHeader));
    return packet;
}


