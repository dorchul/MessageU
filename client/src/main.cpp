#include "Connection.h"
#include "Client.h"
#include "Utils.h"
#include "Protocol.h"
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <chrono>

static void printDivider(const std::string& title) {
    std::cout << "\n================ " << title << " ================\n";
}

int main() {
    std::string ip;
    uint16_t port;

    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info\n";
        return 1;
    }

    // ===== Create two separate connections =====
    Connection connBob;

    if (!connBob.connectToServer(ip, port)) {
        std::cerr << "Failed to connect client.\n";
        return 1;
    }

    Client bob(connBob);

    // ===== 600: Register both =====
    printDivider("Registration");

    std::cout << "[Bob] Registering...\n";
    if (!bob.doRegister("Bob", "data_bob")) return 1;

    connBob.closeConnection();
    return 0;
}
