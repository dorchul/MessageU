#include "Menu.h"
#include "Utils.h"
#include "Client.h"
#include "Protocol.h"

#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <stdexcept>
#include <limits>

void displayMessages(const Client& client, const std::vector<DecodedMessage>& decoded)
{
    if (decoded.empty()) {
        std::cout << "  [No new messages]\n";
        return;
    }

    for (const auto& msg : decoded) {
        // Lookup sender name
        std::string name = client.nameFor(msg.fromHex);
        const std::string& fromDisplay = name.empty() ? msg.fromHex : name;

        std::cout << "From: " << fromDisplay << "\n"
            << "Content: " << msg.text << "\n"
            << "-----<EOM>-----\n";
    }
}


// ===================================================
// Interactive Menu (exception-safe)
// ===================================================
void runMenu(Client& client, const std::string& dataDir)
{
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
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "[!] Invalid option.\n";
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice == 0) {
            std::cout << "Goodbye!\n";
            break;
        }

        try {
            switch (choice) {
            case 110: {
                std::cout << "[Info] Registering user...\n";
                try {
                    if (client.doRegister(dataDir))
                        std::cout << "[+] Registration complete. UUID file saved.\n";
                    else
                        std::cout << "[Info] Already registered.\n";
                }
                catch (const std::exception& e) {
                    std::cerr << "[Error] Registration failed: " << e.what() << "\n";
                }
                break;
            }


            case 120: {
                std::cout << "[Info] Requesting clients list...\n";
                try {
                    auto list = client.requestClientsList();
                    client.cacheClientDirectory(list);

                    if (list.empty()) {
                        std::cout << "[!] No registered clients.\n";
                        break;
                    }

                    std::cout << "[+] Clients list received (" << list.size() << " entries):\n";
                    for (const auto& [uuid, name] : list)
                        std::cout << "    " << name << " | " << Utils::uuidToHex(uuid) << "\n";
                }
                catch (const std::exception& e) {
                    std::cerr << "[Error] Failed to get clients list: " << e.what() << "\n";
                }
                break;
            }

            case 130: {
                std::string target;
                std::cout << "Enter target UUID (hex): ";
                std::getline(std::cin, target);

                if (target.size() != UUID_HEX_LEN) {
                    std::cout << "[!] UUID must be " << UUID_HEX_LEN << " hex chars.\n";
                    break;
                }

                std::cout << "[Info] Requesting public key...\n";

                try {
                    auto key = client.requestPublicKey(target);   // logic-only call
                    std::cout << "[+] Public key request completed - key is now available.\n";
                }
                catch (const std::exception& e) {
                    std::cerr << "[Error] Failed to request public key: " << e.what() << "\n";
                }
                break;
            }

            case 140: {
                std::cout << "[Info] Checking for waiting messages...\n";
                try {
                    auto decoded = client.fetchMessages();
                    if (decoded.empty())
                        std::cout << "[Info] No new messages.\n";
                    else {
                        std::cout << "[+] Received " << decoded.size() << " message(s):\n";
                        displayMessages(client, decoded);
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "[Error] Failed to retrieve messages: " << e.what() << "\n";
                }
                break;
            }

            
            case 150:
            case 151:
            case 152: {
                std::string targetHex;
                std::cout << "Enter recipient UUID (hex): ";
                std::getline(std::cin, targetHex);
                if (targetHex.size() != UUID_HEX_LEN) {
                    std::cout << "[!] UUID must be " << UUID_HEX_LEN << " hex chars.\n";
                    break;
                }

                MessageType type = MessageType::TEXT;
                std::vector<uint8_t> content;

                if (choice == 150) {
                    std::string text;
                    std::cout << "Enter message text: ";
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

                try {
                    auto toUUID = Utils::hexToUUID(targetHex);
                    bool ok = client.sendMessage(toUUID, type, content);

                    if (ok)
                        std::cout << "[+] Message sent successfully.\n";
                    else {
                        if (type == MessageType::REQUEST_SYM)
                            std::cout << "[Info] Symmetric key already exists - request skipped.\n";
                        else if (type == MessageType::TEXT)
                            std::cout << "[!] Message not sent - missing symmetric key or message too large.\n";
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "[Error] Failed to send message: " << e.what() << "\n";
                }
                break;
            }

            default:
                std::cout << "[!] Invalid option.\n";
                break;
            }
        }
        catch (const std::invalid_argument& e) {
            std::cerr << "[Input Error] " << e.what() << "\n";
        }
        catch (const std::runtime_error& e) {
            std::cerr << "[Error] " << e.what() << "\n";
        }
        catch (const std::exception& e) {
            std::cerr << "[Unexpected Error] " << e.what() << "\n";
        }
        catch (...) {
            std::cerr << "[Unknown Error] An unexpected exception occurred.\n";
        }
    }
}
