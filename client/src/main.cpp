#include "Client.h"
#include "Utils.h"
#include <iostream>
#include "Connection.h"

int main()
{
    try {
        std::string name = "Bob";          // change to "Alice" for second test
        std::string dataDir = "data_bob";  // or "data_alice"

        // Read server info (IP:PORT)
        std::string ip;
        uint16_t port;
        if (!Utils::readServerInfo(ip, port)) {
            std::cerr << "Failed to read data/server.info\n";
            return 1;
        }

        // Connect to server
        Connection conn;
        if (!conn.connectToServer(ip, port)) {
            std::cerr << "Failed to connect to server\n";
            return 1;
        }

        // Create client (loads me.info if exists)
        Client client(conn, dataDir);

        std::cout << "================ Registration ================\n";
        if (!client.doRegister(name, dataDir))
            return 1;

        std::cout << "================ Clients List ================\n";
        auto clients = client.requestClientsList();
        if (clients.empty()) {
            std::cout << "No clients returned.\n";
        }
        else {
            for (const auto& [uuid, cname] : clients) {
                std::cout << "- " << cname
                    << " (" << Utils::uuidToHex(uuid) << ")\n";
            }
        }

        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception: " << ex.what() << "\n";
        return 1;
    }
}
