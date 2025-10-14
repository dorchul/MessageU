#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>

class Connection; // forward-declare כדי לא לכלול כאן את Connection.h

class Client {
public:
    explicit Client(Connection& conn)
        : m_conn(conn) {}

    // REGISTER (600)
    bool doRegister(const std::string& name, const std::vector<uint8_t>& pubKey);

    // getters אם צריך בהמשך
    const std::array<uint8_t, 16>& id()   const { return m_clientId; }
    const std::string& name() const { return m_name; }

private:
    Connection& m_conn;                       // שימוש בחיבור שכבר קיים
    std::array<uint8_t, 16> m_clientId{};      // נשמר לאחר רישום
    std::string m_name;
    std::vector<uint8_t> m_pubKey;
};
