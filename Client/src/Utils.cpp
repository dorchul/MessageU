#include "Utils.h"
#include <fstream>
#include <sstream>
#include <iomanip>

bool Utils::readServerInfo(std::string& ip, uint16_t& port) {
    std::ifstream file("data/server.info");
    if (!file.is_open()) return false;

    std::string line;
    std::getline(file, line);
    file.close();

    std::istringstream iss(line);
    std::string portStr;
    if (!std::getline(iss, ip, ':')) return false;
    if (!std::getline(iss, portStr)) return false;

    port = static_cast<uint16_t>(std::stoi(portStr));
    return true;
}

bool Utils::saveMeInfo(const std::string& name, const std::array<uint8_t, 16>& id, const std::vector<uint8_t>& pub) {
    std::ofstream f("data/me.info", std::ios::binary | std::ios::trunc);
    if (!f) return false;

    f << name << "\n";

    for (auto b : id)
        f << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    f << "\n";

    f.write(reinterpret_cast<const char*>(pub.data()), pub.size());
    return true;
}
