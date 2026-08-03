#pragma once

#include <Arduino.h>
#include <map>
#include <string>
#include <vector>

#include "BLEScannerCore.h"

#ifndef NATIVE_TEST
#include <BLEAdvertisedDevice.h>
#include <BLEScan.h>
#include <FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#else
class BLEAdvertisedDevice;
class BLEScanResults;
class BLERemoteCharacteristic;
#endif

namespace mcp {

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

// ---------------------------------------------------------------------------
// BLEScanner — BLE advertising capture + optional GATT enumeration.
//
// Purpose: capture what nearby devices broadcast so the payload format of a
// given app/device can be reverse engineered.  All captured data is exposed
// through MCP JSON-RPC methods (ble/scan, ble/scan/results, ble/scan/stop,
// ble/connect, ble/disconnect, ble/services/start, ble/services/results,
// ble/services/stop).
//
// Threading notes:
//   * startScan() uses the NON-blocking BLEScan::start(duration, cb, false)
//     overload so the calling (MCP) task never blocks on the scan.
//   * The scan-completion callback runs on the Bluetooth controller task
//     (BTC_TASK); it must NOT call esp_ble_gap_stop_scanning() or any other
//     controller API (deadlock + WDT abort).  It only flips a flag.
//   * getServices()/getServicesResults() block briefly (bounded by
//     notifyCaptureMs) to collect notified values — use the two-phase
//     start/results API to keep the MCP task responsive.
// ---------------------------------------------------------------------------
class BLEScanner {
public:
    BLEScanner() = default;

    // Initialise the BLE stack.  Safe to call once at boot.
    void begin();

    // ---- Passive scanning --------------------------------------------------

    // Start an advertising scan for `durationMs` (0 = continuous until stop()).
    // Returns true if a scan was started.  Non-blocking.
    bool startScan(uint32_t durationMs);

    // Stop a running scan.  Safe to call from a normal task context.
    void stopScan();

    // True while a scan is running.
    bool isScanning() const;

    // Snapshot of all reports captured since the last scan start.
    std::vector<BLEAdvReport> getResults();

    // Number of reports in the current snapshot.
    size_t reportCount() const;

    // Reset the captured report list.
    void clearResults();

    // ---- GATT client (two-phase) ------------------------------------------

    // Connect to a peer by MAC ("AA:BB:CC:DD:EE:FF" or "aa:bb:cc:dd:ee:ff").
    // Returns true on success; connection is asynchronous.
    bool connect(const std::string& mac, uint32_t timeoutMs = 5000);

    void disconnect();

    bool isConnected() const;

    // Phase 1: enumerate services + characteristics of the connected device,
    // read readable values, and subscribe to all notifiable/indicatable
    // characteristics.  Returns immediately with the enumeration (notified
    // values are captured asynchronously into the returned structures).
    // NOTE: GATT discovery runs on a dedicated task; a slow/uncooperative
    // peer cannot block the MCP task.  Wait for ready via ble/services/results.
    std::vector<BLEServiceInfo> getServicesStart();

    // Phase 2: wait up to `notifyCaptureMs` for the enumeration (started by
    // getServicesStart) to complete AND for notified/indicated values to
    // arrive, then return the enumeration.  Blocks briefly.
    std::vector<BLEServiceInfo> getServicesResults(uint32_t notifyCaptureMs = 3000);

    // Phase 3: unsubscribe from all notifiable characteristics.
    void getServicesStop();

    // True while the GATT discovery task is still enumerating.
    bool isServicesBusy() const;

    // Advertising report callback (invoked by the BLE stack).
    void onAdv(BLEAdvertisedDevice* adv);

    // Scan completion hook (BLE stack callback, non-blocking start()).
    static void onScanCompleteStatic(BLEScanResults results);

private:
    bool scanning_ = false;
    bool connected_ = false;
    std::string connectedMac_;
    std::vector<BLEAdvReport> reports_;
    std::vector<BLEServiceInfo> services_;
    // MAC -> set of payloads already recorded for that device (dedupe).
    std::map<std::string, std::map<std::string, bool>> seenPayloads_;
    // Registered notify callbacks (per characteristic UUID), released by
    // getServicesStop().
    std::map<std::string, class BLERemoteCharacteristic*> notifyChars_;
    std::map<std::string, std::string> notifyValues_;
#ifndef NATIVE_TEST
    class BLEClient* client_ = nullptr;
    TaskHandle_t gattTaskHandle_ = nullptr;
    SemaphoreHandle_t gattDoneSem_ = nullptr;
    volatile bool gattBusy_ = false;
    volatile bool gattCancelled_ = false;
    void onNotify(class BLERemoteCharacteristic* chr, uint8_t* data, size_t len);
    void gattTaskBody();
    static void gattTaskStatic(void* param);
    void gattWaitFinished(uint32_t timeoutMs);
#endif
};

} // namespace mcp
