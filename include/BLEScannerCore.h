#pragma once

// Pure BLE helper functions — no BLE-stack dependencies, so they can be unit
// tested natively.  Shared by BLEScanner.cpp (device builds) and the native
// test_ble_scanner suite.

#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

namespace mcp {

// One captured BLE advertising report (raw broadcast payload).
struct BLEAdvReport {
    std::string mac;
    std::string name;          // advertised name (may be empty)
    int         rssi;          // dBm (latest)
    // Distinct payloads seen for this MAC, oldest -> newest.  Each entry is the
    // complete raw advertising payload as lowercase hex.  Payload changes are
    // the key signal when reverse-engineering a broadcast format.
    std::vector<std::string> payloadHistory;
    std::string servicesHex;   // advertised 128/32/16-bit service UUIDs, comma-separated
    std::string manufacturer;  // manufacturer data, hex (company id first 2 bytes)
    bool        isConnectable;
    uint64_t    firstSeen;     // millis() of first report
    // Number of DISTINCT payloads captured for this MAC.
    uint32_t    count;
};

// One GATT characteristic discovered on a connected device.
struct BLECharInfo {
    std::string uuid;
    std::string properties;   // read/write/notify/indicate/...
    std::string valueHex;     // last read / notified value (may be empty)
    std::string valueText;    // printable ASCII of valueHex (may be empty)
};

// One GATT service discovered on a connected device.
struct BLEServiceInfo {
    std::string uuid;
    std::vector<BLECharInfo> characteristics;
};

namespace blecore {

// Bounds for the per-device payload history (tunable constants).
constexpr size_t MAX_DEVICES  = 32;   // tracked MACs per scan
constexpr size_t MAX_PAYLOADS = 8;    // distinct payloads per MAC

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

// Record a raw payload into a report's per-device payload history.  Identical
// payloads are skipped; distinct payloads are appended oldest -> newest,
// bounded to MAX_PAYLOADS entries (oldest dropped when full), and the report's
// count tracks the number of distinct payloads currently retained.  The seen
// set stays consistent with the history so an evicted payload can be recorded
// again if it re-broadcasts later.
inline void recordPayload(std::vector<std::string>& history, uint32_t& count,
                          std::map<std::string, bool>& seen,
                          const std::string& payloadHex) {
    if (payloadHex.empty()) return;
    if (seen.count(payloadHex)) return;  // duplicate payload — skip
    seen[payloadHex] = true;
    history.push_back(payloadHex);
    while (history.size() > MAX_PAYLOADS) {  // drop the oldest entry when full
        seen.erase(history.front());
        history.erase(history.begin());
    }
    count = static_cast<uint32_t>(history.size());
}

} // namespace blecore
} // namespace mcp
