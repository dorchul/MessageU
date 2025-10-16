// Prevent Windows headers from defining BOOLEAN, min/max, etc.
#define NOCRYPT
#define NCRYPT
#define NOMINMAX
#include <winsock2.h> 
#include <ws2tcpip.h> 
#include <windows.h> 
#undef min
#undef max

#pragma once

#include <string>
#include <cryptopp/base64.h>



class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
