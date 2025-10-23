# MessageU

MessageU is a secure client–server messaging system developed as part of an advanced defensive programming course.

## Overview
- **Client:** C++ (Visual Studio 2019, Windows)  
- **Server:** Python (TCP socket server), concurrent requests handling 
- **Protocol:** Custom binary (Little Endian) with fixed-size header + variable payload (see protocol folder)
- **Encryption:** RSA (asymmetric) + AES-CBC (symmetric)  
- **Design:** Stateless server; each client reconnects per request  

## Features
- User registration and UUID persistence  
- Public key exchange between clients  
- Encrypted text messaging (end-to-end)  
- Server-side message queue for offline delivery  
- Robust error handling and security-focused protocol logic  

## Runtime Notes
Two small configuration files are required for runtime (not included in submission):

- **Client side:** `data/server.info`  
  ```
  <server_ip> <port>
  ```
  Example:
  ```
  127.0.0.1:1357
  ```

- **Server side:** `myport.info`  
  ```
  <port>
  ```
  Example:
  ```
  1357
  ```

The client reads its file from the `data` subfolder, and the server expects its file in the same directory as `server.py`.  

## Build (Client)
Open **x64 Native Tools Command Prompt for VS 2019** and run:
```cmd
cd client
cl /EHsc /MD /std:c++17 /Fe:MessageUClient.exe *.cpp /I . ^
   /I "C:\vcpkg\installed\x64-windows\include" ^
   /link "C:\vcpkg\installed\x64-windows\lib\cryptopp.lib"
```
> Requires [Crypto++](https://www.cryptopp.com/) installed via vcpkg:  
> `vcpkg install cryptopp:x64-windows`

## ▶️ Run
```cmd
MessageUClient.exe
```
Expected startup message:
```
MessageU client at your service.
```

## Future Improvements

### Security
- Replace static IV in AES-CBC with random IV per message.  
- Switch from AES-CBC to AES-GCM or another authenticated encryption mode for integrity protection.  
- Upgrade to RSA-2048 and verify key authenticity to prevent impersonation.  
- Add forward secrecy using ephemeral key exchange (e.g., Diffie–Hellman).  
- Wrap communication with TLS to prevent active network attacks.  

### Design
- Persist registered users and queued messages in a database (e.g., SQLite).   
- Improve protocol versioning and error reporting.  
- Extend client interface with message history and file attachments.  
- Add automated integration and encryption tests.  

---

*This project was created for academic purposes, demonstrating secure communication design, encryption integration, and defensive coding practices.*
