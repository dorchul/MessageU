#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Protocol.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <array>


// Helper: find UUID by name
static std::array<uint8_t, 16> findClientIdByName(
    const std::vector<std::pair<std::array<uint8_t, 16>, std::string>>& list,
    const std::string& name)
{
    for (const auto& [uuid, nm] : list)
        if (nm == name)
            return uuid;
    return {};
}

// Handle and print pending messages (used by both clients)
static void processMessages(const std::string& selfName,
    const std::vector<PendingMessage>& msgs)
{
    if (msgs.empty()) {
        std::cout << "  [No new messages]\n";
        return;
    }

    for (const auto& msg : msgs) {
        std::string fromHex = Utils::uuidToHex(msg.fromId);
        std::string typeName;
        switch (msg.type) {
        case 1: typeName = "Request Symmetric Key"; break;
        case 2: typeName = "Encrypted AES Key"; break;
        case 3: typeName = "Encrypted Text"; break;
        default: typeName = "Unknown"; break;
        }

        std::cout << "  From: " << fromHex
            << " | Type=" << (int)msg.type
            << " (" << typeName << ")"
            << " | Size=" << msg.content.size() << "\n";

        // Type 2 → decrypt AES key
        if (msg.type == (uint8_t)MessageType::SEND_SYM) {
            try {
                std::string name; std::array<uint8_t, 16> uuid{}; std::vector<uint8_t> priv;
                if (!Utils::loadMeInfo(name, uuid, priv, "data/" + selfName)) {
                    std::cerr << "     Cannot load private key.\n";
                    continue;
                }

                RSAPrivateWrapper rsa((const char*)priv.data(), (unsigned int)priv.size());
                std::string plain = rsa.decrypt((const char*)msg.content.data(),
                    (unsigned int)msg.content.size());
                if (plain.size() != AESWrapper::DEFAULT_KEYLENGTH) {
                    std::cerr << "     Invalid AES key size after decrypt.\n";
                    continue;
                }

                std::filesystem::create_directories("data/symmkeys");
                std::string path = "data/symmkeys/" + fromHex + ".bin";
                std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
                ofs.write(plain.data(), plain.size());
                std::cout << "     Saved decrypted AES key to " << path << "\n";
            }
            catch (...) {
                std::cout << "     (Failed to decrypt AES key)\n";
            }
        }

        // Type 3 → decrypt text
        if (msg.type == (uint8_t)MessageType::TEXT) {
            try {
                std::string keyPath = "data/symmkeys/" + fromHex + ".bin";
                unsigned char rawKey[AESWrapper::DEFAULT_KEYLENGTH]{};
                std::ifstream ifs(keyPath, std::ios::binary);
                if (!ifs.good()) {
                    std::cout << "     (No AES key for sender)\n";
                    continue;
                }
                ifs.read((char*)rawKey, AESWrapper::DEFAULT_KEYLENGTH);
                AESWrapper aes(rawKey, AESWrapper::DEFAULT_KEYLENGTH);
                std::string plain = aes.decrypt((const char*)msg.content.data(),
                    (unsigned int)msg.content.size());
                std::cout << "     Decrypted text: \"" << plain << "\"\n";
            }
            catch (...) {
                std::cout << "     (Text decryption failed)\n";
            }
        }
    }
}

int main() {
    try {
        std::cout << "=== MessageU Handshake Demo - Bob & Alice ===\n\n";

        // --- Server info ---
        std::string ip; uint16_t port;
        if (!Utils::readServerInfo(ip, port)) {
            std::cerr << "Failed to read data/server.info\n";
            return 1;
        }

        std::filesystem::create_directories("data/alice");
        std::filesystem::create_directories("data/bob");
        std::filesystem::create_directories("data/symmkeys");

        Connection aliceConn, bobConn;
        if (!aliceConn.connectToServer(ip, port)) return 1;
        if (!bobConn.connectToServer(ip, port)) return 1;

        Client alice(aliceConn, "data/alice");
        Client bob(bobConn, "data/bob");

        // === 1. REGISTER (600) ===
        alice.doRegister("Alice", "data/alice");
        bob.doRegister("Bob", "data/bob");
        std::cout << "[Alice] registered.\n";
        std::cout << "[Bob] registered.\n\n";
        std::cout << "\n";

        // === 2. CLIENTS LIST (601) ===

        auto listA = alice.requestClientsList();
        auto listB = bob.requestClientsList();

        auto bobId = findClientIdByName(listA, "Bob");
        auto aliceId = findClientIdByName(listB, "Alice");

        std::string bobHex = Utils::uuidToHex(bobId);
        std::string aliceHex = Utils::uuidToHex(aliceId);

        std::cout << "[Alice] Found Bob UUID:   " << bobHex << "\n";
        std::cout << "[Bob]   Found Alice UUID: " << aliceHex << "\n\n";


        // === 3. GET PUBLIC KEY (602) ===

        // Bob requests Alice's public key
        aliceHex = Utils::uuidToHex(aliceId);
        auto alicePubKey = bob.requestPublicKey(aliceHex);

        if (alicePubKey.empty()) {
            std::cerr << "[Bob] Failed to retrieve Alice's public key.\n";
        }
        else {
            std::ostringstream ossA;
            for (size_t i = 0; i < std::min<size_t>(alicePubKey.size(), 32); ++i)
                ossA << std::hex << std::setw(2) << std::setfill('0') << (int)alicePubKey[i];
            std::cout << "[Bob] Retrieved Alice's public key ("
                << alicePubKey.size() << " bytes): "
                << ossA.str() << "...\n";
        }

        // Alice requests Bob's public key
        bobHex = Utils::uuidToHex(bobId);
        auto bobPublicKey = alice.requestPublicKey(bobHex);

        if (bobPublicKey.empty()) {
            std::cerr << "[Alice] Failed to retrieve Bob's public key.\n";
        }
        else {
            std::ostringstream ossB;
            for (size_t i = 0; i < std::min<size_t>(bobPublicKey.size(), 32); ++i)
                ossB << std::hex << std::setw(2) << std::setfill('0') << (int)bobPublicKey[i];
            std::cout << "[Alice] Retrieved Bob's public key ("
                << bobPublicKey.size() << " bytes): "
                << ossB.str() << "...\n";
        }

        std::cout << std::endl;



        // === 4. REQUEST_SYM (603 Type 1) ===
        std::cout << "[Bob] Requests symmetric key from Alice\n";
        bob.sendMessage(aliceId, MessageType::REQUEST_SYM, {});
        std::cout << "\n";

        // === 5. ALICE GET WAITING (604) ===
        std::cout << "[Alice] Requests waiting messages\n";
        auto aliceMsgs = alice.requestWaitingMessages();
        processMessages("alice", aliceMsgs);
        std::cout << "\n";

        // === 6. ALICE GET PUBLIC KEY (602) ===
        std::cout << "[Alice] Requests Bob's public key)\n";
        auto bobPubKey = alice.requestPublicKey(bobHex);
        std::cout << "[Alice] Retrieved Bob's public key (" << bobPubKey.size() << " bytes).\n\n";

        // === 7. SEND_SYM (603 Type 2) ===
        std::cout << "[Alice] Sends AES key to Bob\n";
        alice.sendMessage(bobId, MessageType::SEND_SYM, {});
        std::cout << "\n";

        // === 8. BOB GET WAITING (604) ===
        std::cout << "[Bob] Requests waiting messages\n";
        auto bobMsgs = bob.requestWaitingMessages();
        processMessages("bob", bobMsgs);
        std::cout << "\n";

        // === 9. TEXT (603 Type 3) ===
        std::string text = "Hello Alice, this is Bob.";
        std::vector<uint8_t> content(text.begin(), text.end());
        std::cout << "[Bob] Sends encrypted text to Alice\n";
        bob.sendMessage(aliceId, MessageType::TEXT, content);
        std::cout << "\n";

        // === 10. ALICE GET WAITING (604) ===
        std::cout << "[Alice] Requests waiting messages\n";
        auto aliceMsgs2 = alice.requestWaitingMessages();
        processMessages("alice", aliceMsgs2);
        std::cout << "\n";

        std::cout << "Done: handshake + encrypted text delivered\n";
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
