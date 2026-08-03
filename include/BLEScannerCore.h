#pragma once

// Pure BLE helper functions — no BLE-stack dependencies, so they can be unit
// tested natively.  Shared by BLEScanner.cpp (device builds) and the native
// test_ble_scanner suite.

#include <cstdint>
#include <cstdlib>
#include <string>

namespace mcp {
namespace blecore {

// Encode raw bytes as lowercase hex ("" for empty input).
inline std::string hexEncode(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

// Render a hex string as printable ASCII (non-printables become '.').
inline std::string hexToAscii(const std::string& hex) {
    std::string out;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        char c = static_cast<char>(strtol(hex.substr(i, 2).c_str(), nullptr, 16));
        if (c >= 0x20 && c <= 0x7E) out.push_back(c);
        else out.push_back('.');
    }
    return out;
}

// Decode a hex string into raw bytes.  Returns false on odd-length input or
// non-hex characters (out is unchanged then).
inline bool hexDecode(const std::string& hex, std::string& out) {
    if (hex.length() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        int hi = strtol(hex.substr(i, 1).c_str(), nullptr, 16);
        int lo = strtol(hex.substr(i + 1, 1).c_str(), nullptr, 16);
        if ((hex[i] != '0' && hi == 0) || (hex[i + 1] != '0' && lo == 0)) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

// BLE flags AD type (0x01): bit1 LE General Discoverable, bit2 LE Limited
// Discoverable, bit3 BR/EDR Not Supported, bit4 LE+BR/EDR Simultaneous.
// Heuristic: a broadcast is "connectable" when the BR/EDR-Not-Supported bit is
// clear.  A set bit indicates a beacon-style device that advertises BR/EDR
// support only (typically non-connectable over LE).  When the flags AD is
// absent or malformed we optimistically assume connectable.
inline bool payloadIsConnectable(const uint8_t* payload, size_t len) {
    size_t i = 0;
    while (i + 1 < len) {
        uint8_t adLen = payload[i];
        if (adLen == 0) break;
        if (i + 1 + adLen > len) break;
        uint8_t adType = payload[i + 1];
        if (adType == 0x01 && adLen >= 2) {
            return (payload[i + 2] & 0x04) == 0;
        }
        i += adLen + 1;
    }
    return true;
}

} // namespace blecore
} // namespace mcp
