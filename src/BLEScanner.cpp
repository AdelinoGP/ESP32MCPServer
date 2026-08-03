#ifndef NATIVE_TEST

#include "BLEScanner.h"
#include "BLEScannerCore.h"
#include <BLEAddress.h>
#include <BLEAdvertisedDevice.h>
#include <BLEClient.h>
#include <BLEDevice.h>
#include <BLERemoteCharacteristic.h>
#include <BLERemoteDescriptor.h>
#include <BLERemoteService.h>
#include <BLEScan.h>
#include <BLEUUID.h>
#include <BLEUtils.h>
#include <ArduinoJson.h>

namespace mcp {

using blecore::MAX_DEVICES;
using blecore::MAX_PAYLOADS;
using blecore::hexEncode;
using blecore::hexToAscii;
using blecore::payloadIsConnectable;
using blecore::recordPayload;

// ---------------------------------------------------------------------------
// Advertising callback — merges duplicate reports per MAC so the raw payload
// stays available even when a device does not re-advertise identical data.
// ---------------------------------------------------------------------------

class ScannerCallback : public BLEAdvertisedDeviceCallbacks {
public:
    explicit ScannerCallback(BLEScanner* owner) : owner_(owner) {}
    void onResult(BLEAdvertisedDevice advertisedDevice) override {
        owner_->onAdv(&advertisedDevice);
    }
private:
    BLEScanner* owner_;
};

// The BLE stack invokes a plain C-style callback on scan completion; route it
// to the singleton instance so the MCP task is never blocked by the scan.
//
// IMPORTANT: this callback runs on the Bluetooth controller task (BTC_TASK).
// Do NOT call esp_ble_gap_stop_scanning() (e.g. via stopScan()) from here —
// it is a re-entrant controller call that deadlocks the task and trips the
// watchdog.  The scan has already finished; clearing the flag is sufficient.
static BLEScanner* g_instance = nullptr;
void BLEScanner::onScanCompleteStatic(BLEScanResults) {
    if (g_instance != nullptr) g_instance->scanning_ = false;
}

void BLEScanner::begin() {
    BLEDevice::init("");
    g_instance = this;
}

bool BLEScanner::startScan(uint32_t durationMs) {
    if (scanning_) return false;
    reports_.clear();
    seenPayloads_.clear();
    scanning_ = true;
    BLEScan* scan = BLEDevice::getScan();
    // wantDuplicates=true: deliver every advertisement to the callback so the
    // per-device payload history can capture payload changes.  The library
    // frees each BLEAdvertisedDevice after onResult() returns, so the heap
    // stays bounded even on a busy radio environment.
    scan->setAdvertisedDeviceCallbacks(new ScannerCallback(this), true);
    // Active scan requests scan responses (more data, e.g. names).
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(99);
    // Non-blocking start: the completion callback fires when the duration
    // elapses; the MCP task must never block on the scan.  Round milliseconds
    // UP to whole seconds (0 would mean continuous scan until stop()).
    uint32_t seconds = (durationMs + 999) / 1000;
    if (seconds == 0) seconds = 1;
    scan->start(seconds, onScanCompleteStatic, false);
    return true;
}

void BLEScanner::stopScan() {
    if (!scanning_) return;
    scanning_ = false;
    BLEDevice::getScan()->stop();
}

bool BLEScanner::isScanning() const {
    return scanning_;
}

std::vector<BLEAdvReport> BLEScanner::getResults() {
    return reports_;
}

size_t BLEScanner::reportCount() const {
    return reports_.size();
}

void BLEScanner::clearResults() {
    reports_.clear();
    seenPayloads_.clear();
}

void BLEScanner::onAdv(BLEAdvertisedDevice* adv) {
    if (adv == nullptr) return;

    std::string mac = adv->getAddress().toString();
    std::string payloadHex;
    uint8_t* raw = adv->getPayload();
    size_t rawLen = adv->getPayloadLength();
    if (raw != nullptr && rawLen > 0) {
        payloadHex = hexEncode(raw, rawLen);
    }

    // Merge duplicate reports for the same MAC.
    for (auto& r : reports_) {
        if (r.mac == mac) {
            r.rssi = adv->getRSSI();
            recordPayload(r.payloadHistory, r.count, seenPayloads_[r.mac], payloadHex);
            return;
        }
    }

    // New device — enforce the device cap (FIFO eviction).
    while (reports_.size() >= MAX_DEVICES) {
        seenPayloads_.erase(reports_.front().mac);
        reports_.erase(reports_.begin());
    }

    BLEAdvReport rep;
    rep.mac = mac;
    rep.rssi = adv->getRSSI();
    rep.isConnectable = payloadIsConnectable(raw, rawLen);
    rep.firstSeen = millis();
    rep.count = 0;

    if (adv->haveName()) rep.name = adv->getName().c_str();

    // Advertised service UUIDs (128-bit / 32-bit / 16-bit, as reported).
    for (int i = 0; i < adv->getServiceUUIDCount(); ++i) {
        std::string s = adv->getServiceUUID(i).toString();
        if (!rep.servicesHex.empty()) rep.servicesHex += ",";
        rep.servicesHex += s;
    }

    // Manufacturer specific data (company id + data).
    if (adv->haveManufacturerData()) {
        std::string md = adv->getManufacturerData();
        rep.manufacturer = hexEncode(reinterpret_cast<const uint8_t*>(md.data()),
                                     md.length());
    }

    reports_.push_back(rep);
    recordPayload(reports_.back().payloadHistory, reports_.back().count,
                  seenPayloads_[rep.mac], payloadHex);
}

// ---------------------------------------------------------------------------
// GATT client (two-phase: start / results / stop)
// ---------------------------------------------------------------------------

bool BLEScanner::connect(const std::string& mac, uint32_t timeoutMs) {
    if (connected_ || client_ != nullptr) return false;
    BLEClient* client = BLEDevice::createClient();
    if (client == nullptr) return false;
    if (!client->connect(BLEAddress(mac))) {
        client_ = nullptr;
        return false;
    }
    client_ = client;
    connected_ = true;
    connectedMac_ = mac;
    services_.clear();
    notifyChars_.clear();
    notifyValues_.clear();
    return true;
}

void BLEScanner::disconnect() {
    getServicesStop();
    gattWaitFinished(2000);  // let the GATT task finish before freeing the client
    if (client_ != nullptr) {
        if (client_->isConnected()) client_->disconnect();
        client_ = nullptr;
    }
    connected_ = false;
    services_.clear();
}

bool BLEScanner::isConnected() const {
    return connected_;
}

// ---------------------------------------------------------------------------
// GATT enumeration runs on a dedicated task: the 2.0.17 BLE library has no
// timeouts on the discovery/read semaphores, so a slow or uncooperative peer
// would otherwise block the MCP task forever.  The task signals completion
// via a semaphore; getServicesResults() waits on it with a bound.
// ---------------------------------------------------------------------------

std::vector<BLEServiceInfo> BLEScanner::getServicesStart() {
    if (!connected_ || client_ == nullptr) return services_;
    if (gattBusy_) return services_;

    services_.clear();
    notifyChars_.clear();
    notifyValues_.clear();

    if (gattDoneSem_ == nullptr) {
        gattDoneSem_ = xSemaphoreCreateBinary();
    } else {
        xSemaphoreTake(gattDoneSem_, 0);  // discard any stale signal
    }
    gattBusy_ = true;
    gattCancelled_ = false;

    if (gattTaskHandle_ != nullptr) {
        vTaskDelete(gattTaskHandle_);  // previous task must have finished
        gattTaskHandle_ = nullptr;
    }
    xTaskCreatePinnedToCore(gattTaskStatic, "BLEGattTask", 8192, this, 1,
                            &gattTaskHandle_, 0);
    return services_;
}

void BLEScanner::gattTaskStatic(void* param) {
    static_cast<BLEScanner*>(param)->gattTaskBody();
}

void BLEScanner::gattTaskBody() {
    // Enumerate services + characteristics; reads may take seconds on a slow
    // peer.  The MCP task is never blocked by this.
    for (auto& [uuid, svc] : *client_->getServices()) {
        if (svc == nullptr) continue;
        BLEServiceInfo si;
        si.uuid = svc->getUUID().toString();

        for (auto& [cuuid, chr] : *svc->getCharacteristics()) {
            if (chr == nullptr) continue;
            BLECharInfo ci;
            ci.uuid = chr->getUUID().toString();

            if (chr->canRead())            ci.properties += "read,";
            if (chr->canWrite())           ci.properties += "write,";
            if (chr->canWriteNoResponse()) ci.properties += "write-no-response,";
            if (chr->canNotify())          ci.properties += "notify,";
            if (chr->canIndicate())        ci.properties += "indicate,";
            if (chr->canBroadcast())       ci.properties += "broadcast,";
            if (!ci.properties.empty()) ci.properties.pop_back();

            if (chr->canRead()) {
                std::string val = chr->readValue();
                ci.valueHex = hexEncode(reinterpret_cast<const uint8_t*>(val.data()),
                                        val.length());
                ci.valueText = hexToAscii(ci.valueHex);
            }

            if (chr->canNotify() || chr->canIndicate()) {
                chr->registerForNotify(
                    [this](BLERemoteCharacteristic* c, uint8_t* data, size_t len, bool) {
                        this->onNotify(c, data, len);
                    },
                    true);
                notifyChars_[ci.uuid] = chr;
            }

            si.characteristics.push_back(ci);
        }
        services_.push_back(si);
        if (gattCancelled_) break;
    }

    gattBusy_ = false;
    if (gattDoneSem_ != nullptr) xSemaphoreGive(gattDoneSem_);
    gattTaskHandle_ = nullptr;
    vTaskDelete(nullptr);
}

void BLEScanner::onNotify(BLERemoteCharacteristic* chr, uint8_t* data, size_t len) {
    if (chr == nullptr) return;
    std::string value(data, data + len);
    notifyValues_[chr->getUUID().toString()] = value;
}

std::vector<BLEServiceInfo> BLEScanner::getServicesResults(uint32_t notifyCaptureMs) {
    // Wait for enumeration to finish (bounded by the caller's timeout).
    uint32_t waited = 0;
    const uint32_t enumLimit = notifyCaptureMs + 10000;  // 10s cap on discovery
    while (gattBusy_ && waited < enumLimit) {
        delay(50);
        waited += 50;
    }

    // Then wait for notified/indicated values to arrive.
    waited = 0;
    while (!notifyChars_.empty() && waited < notifyCaptureMs) {
        delay(50);
        waited += 50;
        if (!notifyValues_.empty()) {
            for (auto& [uuid, val] : notifyValues_) {
                for (auto& svc : services_) {
                    for (auto& chr : svc.characteristics) {
                        if (chr.uuid == uuid) {
                            chr.valueHex = hexEncode(
                                reinterpret_cast<const uint8_t*>(val.data()),
                                val.length());
                            chr.valueText = hexToAscii(chr.valueHex);
                        }
                    }
                }
            }
            notifyValues_.clear();
        }
    }
    return services_;
}

void BLEScanner::getServicesStop() {
    // Ask the discovery task to bail out early if it is still running.
    if (gattBusy_) gattCancelled_ = true;
    // Unsubscribe to keep the stack clean.
    for (auto& [uuid, chr] : notifyChars_) {
        if (chr != nullptr) chr->registerForNotify(nullptr, false);
    }
    notifyChars_.clear();
    notifyValues_.clear();
}

void BLEScanner::gattWaitFinished(uint32_t timeoutMs) {
    if (!gattBusy_) return;
    if (gattDoneSem_ != nullptr) {
        xSemaphoreTake(gattDoneSem_, pdMS_TO_TICKS(timeoutMs));
    }
    // The task clears gattBusy_ itself when it exits.
    uint32_t waited = 0;
    while (gattBusy_ && waited < timeoutMs) {
        delay(10);
        waited += 10;
    }
    if (gattTaskHandle_ != nullptr && !gattBusy_) {
        gattTaskHandle_ = nullptr;
    }
}

bool BLEScanner::isServicesBusy() const {
    return gattBusy_;
}

} // namespace mcp

#endif // NATIVE_TEST
