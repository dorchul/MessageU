#pragma once
#include <string>
#include <cstdint>
#include <array>
#include <vector>


namespace Utils {
    bool readServerInfo(std::string& ip, uint16_t& port);
    bool saveMeInfo(const std::string& name, const std::array<uint8_t, 16>& id, const std::vector<uint8_t>& pub);
}
