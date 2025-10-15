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
    Connection connAlice;

    if (!connBob.connectToServer(ip, port) || !connAlice.connectToServer(ip, port)) {
        std::cerr << "Failed to connect clients.\n";
        return 1;
    }

    Client bob(connBob);
    Client alice(connAlice);

    // ===== 600: Register both =====
    printDivider("Registration");
    std::vector<uint8_t> dummyKey(160, 0x42);

    std::cout << "[Bob] Registering...\n";
    if (!bob.doRegister("Bob", dummyKey)) return 1;
    std::cout << "[Alice] Registering...\n";
    if (!alice.doRegister("Alice", dummyKey)) return 1;

    // ===== 601: Each requests client list =====
    printDivider("Clients List");
    auto listBob = bob.requestClientsList();
    auto listAlice = alice.requestClientsList();

    std::cout << "[Bob] sees:\n";
    for (const auto& c : listBob)
        std::cout << "  - " << c.second << " (" << Utils::uuidToHex(c.first) << ")\n";

    std::cout << "[Alice] sees:\n";
    for (const auto& c : listAlice)
        std::cout << "  - " << c.second << " (" << Utils::uuidToHex(c.first) << ")\n";

    // ===== Bob finds Alice UUID =====
    std::array<uint8_t, 16> aliceUUID{};
    for (const auto& c : listBob)
        if (c.second == "Alice")
            aliceUUID = c.first;

    // ===== Bob requests Alice’s public key (602) =====
    printDivider("Bob Requests Alice Public Key");
    std::string aliceUUIDstr(reinterpret_cast<const char*>(aliceUUID.data()), 16);
    auto alicePK = bob.requestPublicKey(aliceUUIDstr);
    std::cout << "[Bob] Got Alice’s key (" << alicePK.size() << " bytes)\n";

    // ===== Bob sends message to Alice (603) =====
    printDivider("Bob Sends Message to Alice");
    std::string msgToAlice = "Hello Alice, this is Bob!";
    std::vector<uint8_t> msgContent(msgToAlice.begin(), msgToAlice.end());
    bob.sendMessage(aliceUUID, MessageType::TEXT, msgContent);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ===== Alice requests waiting messages (604) =====
    printDivider("Alice Requests Waiting Messages");
    alice.requestWaitingMessages();

    // ===== Alice requests Bob’s public key (602) =====
    printDivider("Alice Requests Bob Public Key");
    std::array<uint8_t, 16> bobUUID{};
    for (const auto& c : listAlice)
        if (c.second == "Bob")
            bobUUID = c.first;
    std::string bobUUIDstr(reinterpret_cast<const char*>(bobUUID.data()), 16);
    auto bobPK = alice.requestPublicKey(bobUUIDstr);
    std::cout << "[Alice] Got Bob’s key (" << bobPK.size() << " bytes)\n";

    // ===== Alice sends confirmation back to Bob (603) =====
    printDivider("Alice Sends Reply to Bob");
    std::string msgToBob = "Hi Bob! I got your message.";
    std::vector<uint8_t> reply(msgToBob.begin(), msgToBob.end());
    alice.sendMessage(bobUUID, MessageType::TEXT, reply);

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // ===== Bob checks waiting messages (604) =====
    printDivider("Bob Requests Waiting Messages");
    bob.requestWaitingMessages();

    printDivider("Conversation Complete");
    connBob.closeConnection();
    connAlice.closeConnection();
    return 0;
}
