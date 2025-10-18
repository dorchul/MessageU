#pragma once
#include "Client.h"
#include <string>

// Runs the interactive user menu for MessageU
void runMenu(Client& client, const std::string& dataDir);

// Display decoded messages on screen
void displayMessages(const std::vector<DecodedMessage>& decoded);
