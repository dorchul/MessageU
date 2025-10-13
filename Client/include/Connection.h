#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <winsock2.h>   // Windows sockets
#pragma comment(lib, "ws2_32.lib")

class Connection {
public:
    Connection();
    ~Connection();

    bool connectToServer(const std::string& ip, uint16_t port);
    bool sendAll(const uint8_t* data, size_t size);
    bool recvAll(uint8_t* buffer, size_t size);
    void closeConnection();

private:
    SOCKET sock;
    bool connected;
};
