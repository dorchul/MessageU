#pragma once
#include <string>
#include <cstdint>

namespace Utils {
    bool readServerInfo(std::string& ip, uint16_t& port);
}
