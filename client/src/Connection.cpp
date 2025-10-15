#include "Connection.h"
#include <iostream>
#include <ws2tcpip.h>

Connection::Connection() : sock(INVALID_SOCKET), connected(false) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
    }
}

Connection::~Connection() {
    closeConnection();
    WSACleanup();
}

bool Connection::connectToServer(const std::string& ip, uint16_t port) {
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        return false;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    InetPtonA(AF_INET, ip.c_str(), &serverAddr.sin_addr);


    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        sock = INVALID_SOCKET;
        return false;
    }

    connected = true;
    return true;
}

bool Connection::sendAll(const uint8_t* data, size_t size) {
    size_t totalSent = 0;
    while (totalSent < size) {
        int sent = send(sock, reinterpret_cast<const char*>(data + totalSent), (int)(size - totalSent), 0);
        if (sent == SOCKET_ERROR) return false;
        totalSent += sent;
    }
    return true;
}

bool Connection::recvAll(uint8_t* buffer, size_t size) {
    size_t totalRecv = 0;
    while (totalRecv < size) {
        int recvd = recv(sock, reinterpret_cast<char*>(buffer + totalRecv), (int)(size - totalRecv), 0);
        if (recvd <= 0) return false;
        totalRecv += recvd;
    }
    return true;
}

void Connection::closeConnection() {
    if (connected) {
        closesocket(sock);
        connected = false;
    }
}
