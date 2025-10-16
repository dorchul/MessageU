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

#include <cryptopp/modes.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

#include <string>
#include <utility>

// =============================
// RSA Public Key Wrapper
// =============================
class RSAPublicWrapper
{
public:
    static const unsigned int KEYSIZE = 160;
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PublicKey _publicKey;

    RSAPublicWrapper(const RSAPublicWrapper& rsapublic);
    RSAPublicWrapper& operator=(const RSAPublicWrapper& rsapublic);

public:
    RSAPublicWrapper(const char* key, unsigned int length);
    RSAPublicWrapper(const std::string& key);
    ~RSAPublicWrapper();

    std::string getPublicKey() const;
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string encrypt(const std::string& plain);
    std::string encrypt(const char* plain, unsigned int length);
};

// =============================
// RSA Private Key Wrapper
// =============================
class RSAPrivateWrapper
{
public:
    static const unsigned int BITS = 1024;

private:
    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PrivateKey _privateKey;

    RSAPrivateWrapper(const RSAPrivateWrapper& rsaprivate);
    RSAPrivateWrapper& operator=(const RSAPrivateWrapper& rsaprivate);

public:
    RSAPrivateWrapper();
    RSAPrivateWrapper(const char* key, unsigned int length);
    RSAPrivateWrapper(const std::string& key);
    ~RSAPrivateWrapper();

    std::string getPrivateKey() const;
    char* getPrivateKey(char* keyout, unsigned int length) const;

    std::string getPublicKey() const;
    char* getPublicKey(char* keyout, unsigned int length) const;

    std::string decrypt(const std::string& cipher);
    std::string decrypt(const char* cipher, unsigned int length);
};
