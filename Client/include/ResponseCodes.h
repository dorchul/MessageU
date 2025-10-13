#pragma once

// Response codes received from server
enum ResponseCode {
    REGISTER_SUCCESS = 2100,
    CLIENT_LIST = 2101,
    PUBLIC_KEY = 2102,
    MESSAGE_SENT = 2103,
    INCOMING_MESSAGES = 2104,
    GENERAL_ERROR = 9000
};
