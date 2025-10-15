#pragma once
#include <cstdint>
#include <vector>

// ===== Protocol Constants =====
constexpr uint8_t VERSION = 1;

// ===== Request Codes =====
enum class RequestCode : uint16_t {
    REGISTER = 600,
    GET_CLIENTS_LIST = 601,
    GET_PUBLIC_KEY = 602,
    SEND_MESSAGE = 603,
    GET_WAITING_MESSAGES = 604
};

// ===== Response Codes =====
enum class ResponseCode : uint16_t {
    REGISTRATION_OK = 2100,
    CLIENTS_LIST = 2101,
    PUBLIC_KEY = 2102,
    MESSAGE_RECEIVED = 2103,
    WAITING_MESSAGES = 2104,
    _ERROR_ = 9000
};

// ===== Message Types =====
enum class MessageType : uint8_t {
    REQUEST_SYM = 1,  // request symmetric key
    SEND_SYM = 2,  // send symmetric key (RSA encrypted)
    TEXT = 3,  // send text message (AES encrypted)
    FILE = 4   // bonus: send file
};

// ===== Message Header Structures =====
#pragma pack(push, 1)
struct RequestHeader {
    uint8_t clientID[16];
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};

struct ResponseHeader {
    uint8_t version;
    uint16_t code;
    uint32_t payloadSize;
};
#pragma pack(pop)

// ===== Message Payload (603) =====
#pragma pack(push, 1)
struct MessagePayload {
    uint8_t toClientID[16];
    uint8_t type;         // see MessageType
    uint32_t contentSize; // length of content
    // Followed by variable-sized content
};
#pragma pack(pop)

// ===== Utility Functions =====
namespace Protocol {
    // Endian conversions
    uint16_t toLittleEndian16(uint16_t value);
    uint32_t toLittleEndian32(uint32_t value);
    uint16_t fromLittleEndian16(uint16_t value);
    uint32_t fromLittleEndian32(uint32_t value);

    // === Packet builders ===
    std::vector<uint8_t> buildClientListRequest(const uint8_t clientID[16]);
    std::vector<uint8_t> buildSendMessageRequest(
        const uint8_t clientID[16],
        const uint8_t toClientID[16],
        MessageType type,
        const std::vector<uint8_t>& content
    );
}
