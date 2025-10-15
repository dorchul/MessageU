#include "Protocol.h"
#include <cstring>
#include <iostream>
#include <vector>

// ===== Endian Conversion =====
static bool isLittleEndian() {
    uint16_t num = 1;
    return *reinterpret_cast<uint8_t*>(&num) == 1;
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

// ===== Serialization Test =====
void testHeaderSerialization() {
    RequestHeader req{};
    std::memset(req.clientID, 0xAB, 16);
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

// ===== Build "Request Clients List" Packet =====
std::vector<uint8_t> Protocol::buildClientListRequest(const uint8_t clientID[16]) {
    RequestHeader header{};
    std::memcpy(header.clientID, clientID, 16);
    header.version = VERSION;
    header.code = toLittleEndian16(static_cast<uint16_t>(RequestCode::GET_CLIENTS_LIST));
    header.payloadSize = toLittleEndian32(0); // No payload

    std::vector<uint8_t> buffer(sizeof(RequestHeader));
    std::memcpy(buffer.data(), &header, sizeof(RequestHeader));
    return buffer;
}

// ===== Build "Send Message" Request (603) =====
//
// Format:
// [Header]
//   clientID(16) | version(1) | code(2) | payloadSize(4)
// [Payload]
//   toClientID(16) | type(1) | contentSize(4) | content(variable)
std::vector<uint8_t> Protocol::buildSendMessageRequest(
    const uint8_t clientID[16],
    const uint8_t toClientID[16],
    MessageType type,
    const std::vector<uint8_t>& content)
{
    // ---- Prepare payload ----
    MessagePayload payload{};
    std::memcpy(payload.toClientID, toClientID, 16);
    payload.type = static_cast<uint8_t>(type);
    payload.contentSize = toLittleEndian32(static_cast<uint32_t>(content.size()));

    const uint32_t payloadSize = sizeof(MessagePayload) + static_cast<uint32_t>(content.size());

    // ---- Build header ----
    RequestHeader header{};
    std::memcpy(header.clientID, clientID, 16);
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

#ifdef PROTOCOL_TEST
int main() {
    testHeaderSerialization();
    return 0;
}
#endif
