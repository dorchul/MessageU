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

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;

class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 16;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);
public:
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	AESWrapper();
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);
};