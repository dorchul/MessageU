#include "Protocol.h"
#include <cstring>
#include <iostream>

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

#ifdef PROTOCOL_TEST
int main() {
    testHeaderSerialization();
    return 0;
}
#endif

