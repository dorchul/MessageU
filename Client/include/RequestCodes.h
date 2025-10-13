#pragma once

// Request codes sent from client to server
enum RequestCode {
    REGISTER = 600,
    GET_CLIENTS_LIST = 601,
    GET_PUBLIC_KEY = 602,
    SEND_MESSAGE = 603,
    REQUEST_PENDING_MESSAGES = 604
};
