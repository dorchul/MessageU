#include "Menu.h"
#include "Utils.h"
#include <iostream>
#include <vector>
#include <array>
#include <iomanip>

void displayMessages(const std::vector<DecodedMessage>& decoded)
{
    if (decoded.empty()) {
        std::cout << "  [No new messages]\n";
        return;
    }

    for (const auto& msg : decoded) {
        std::string typeName;
        switch (msg.type) {
        case MessageType::REQUEST_SYM: typeName = "Request Symmetric Key"; break;
        case MessageType::SEND_SYM: typeName = "Encrypted AES Key"; break;
        case MessageType::TEXT: typeName = "Encrypted Text"; break;
        default: typeName = "Unknown"; break;
        }

        std::cout << "From: " << msg.fromHex
            << " | Type=" << (int)msg.type
            << " (" << typeName << ")\n"
            << "     " << msg.text << "\n";
    }
}

// ===================================================
// Interactive Menu
// ===================================================
void runMenu(Client& client, const std::string& dataDir)
{
    std::unordered_map<std::string, std::vector<uint8_t>> knownClients; // RAM cache for public keys

    std::cout << "\nMessageU client at your service.\n";
    while (true) {
        std::cout <<
            "\n110) Register\n"
            "120) Request for clients list\n"
            "130) Request for public key\n"
            "140) Request for waiting messages\n"
            "150) Send a text message\n"
            "151) Send a request for symmetric key\n"
            "152) Send your symmetric key\n"
            "0) Exit client\n? ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        if (choice == 0) {
            std::cout << "Goodbye!\n";
            break;
        }

        switch (choice) {
        case 110: {
            std::string name;
            std::cout << "Enter your name: ";
            std::cin >> name;
            if (client.doRegister(name, dataDir))
                std::cout << "[+] Registered successfully as " << name << "\n";
            else
                std::cout << "[!] Registration failed.\n";
            break;
        }
        case 120: {
            auto list = client.requestClientsList();
            if (list.empty()) {
                std::cout << "[!] No clients found.\n";
                break;
            }
            std::cout << "--- Clients List ---\n";
            for (const auto& [uuid, name] : list)
                std::cout << "Name: " << name
                << " | UUID: " << Utils::uuidToHex(uuid) << "\n";
            break;
        }
        case 130: {
            std::string target;
            std::cout << "Enter target UUID (hex): ";
            std::cin >> target;
            auto key = client.requestPublicKey(target);
            if (key.empty())
                std::cout << "[!] Failed to retrieve key.\n";
            else {
                knownClients[target] = key;
                std::cout << "[+] Public key retrieved and cached (" << key.size() << " bytes)\n";
            }
            break;
        }
        case 140: {
            auto msgs = client.requestWaitingMessages();
            auto decoded = client.decodeMessages(msgs);
            displayMessages(decoded);
            break;
        }
        case 150:
        case 151:
        case 152: {
            std::string targetHex;
            std::cout << "Enter recipient UUID (hex): ";
            std::cin >> targetHex;

            MessageType type = MessageType::TEXT;
            std::vector<uint8_t> content;

            if (choice == 150) {
                std::string text;
                std::cout << "Enter message text: ";
                std::cin.ignore();
                std::getline(std::cin, text);
                content.assign(text.begin(), text.end());
                type = MessageType::TEXT;
            }
            else if (choice == 151) {
                type = MessageType::REQUEST_SYM;
            }
            else if (choice == 152) {
                type = MessageType::SEND_SYM;
            }

            auto toUUID = Utils::hexToUUID(targetHex);
            if (client.sendMessage(toUUID, type, content))
                std::cout << "[+] Message sent successfully.\n";
            else
                std::cout << "[!] Failed to send message.\n";
            break;
        }
        default:
            std::cout << "[!] Invalid option.\n";
            break;
        }
    }
}
