#include "Connection.h"
#include "Protocol.h"
#include <stdexcept>
#include <iostream>
#include <ws2tcpip.h>

Connection::Connection() : sock(INVALID_SOCKET), connected(false) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("Connection Error: WSAStartup failed");  // prefixed error
    }
}

Connection::~Connection() noexcept {
    try {
        closeConnection();
        static bool cleanedUp = false; // prevent double cleanup
        if (!cleanedUp) {
            WSACleanup();
            cleanedUp = true;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[Warning] Exception in Connection destructor: " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "[Warning] Unknown exception in Connection destructor.\n";
    }
}

bool Connection::connectToServer(const std::string& ip, uint16_t port) {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        throw std::runtime_error("Connection Error: Socket creation failed");;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    if (InetPtonA(AF_INET, ip.c_str(), &serverAddr.sin_addr) <= 0) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        throw std::runtime_error("Connection Error: Invalid IP address format: " + ip);
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        throw std::runtime_error("Connection Error: Failed to connect to " + ip + ":" + std::to_string(port));
    }

    connected = true;
    return true;
}

bool Connection::sendAll(const uint8_t* data, size_t size) {
    if (!connected) throw std::runtime_error("Connection Error: Attempt to send on disconnected socket");

    if (size > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("Connection Error: Payload too large");
    
    size_t totalSent = 0;
    while (totalSent < size) {
        int sent = send(sock, reinterpret_cast<const char*>(data + totalSent),
            static_cast<int>(size - totalSent), 0);
        if (sent == SOCKET_ERROR) {
            throw std::runtime_error("Connection Error: send() failed");
        }
        totalSent += sent;
    }
    return true;
}

bool Connection::recvAll(uint8_t* buffer, size_t size) {
    if (!connected) throw std::runtime_error("Attempt to receive on disconnected socket");
    
    if (size > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("Connection Error: Payload too large");
    
    size_t totalRecv = 0;
    while (totalRecv < size) {
        int recvd = recv(sock, reinterpret_cast<char*>(buffer + totalRecv),
            static_cast<int>(size - totalRecv), 0);
        if (recvd <= 0) {
            throw std::runtime_error("Connection Error: recv() failed or connection closed");
        }
        totalRecv += recvd;
    }
    return true;
}

void Connection::closeConnection() noexcept {
    if (connected) {
        closesocket(sock);
        connected = false;
        sock = INVALID_SOCKET;
    }
}
