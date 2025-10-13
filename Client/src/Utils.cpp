#include "Utils.h"
#include <fstream>
#include <sstream>

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
