#pragma once
#include "configuration.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "OtaStaging.h"
#include "SinglePortModule.h"
#include "concurrency/OSThread.h"
#include "ota_common/admin_key_verifier.h"
#include "ota_common/merkle.h"
#include "ota_common/transport.h"
#include <memory>
#include <vector>

// Fork frame types on LORA_OTA_APP, after ota-common's 1..11.
enum class LoraOtaExtFrame : uint8_t {
    Query = 12,      // any -> node: reply with Status
    Status = 13,     // node -> asker
    SeedTo = 15,     // admin (PKI) -> node: seed the staged image to a 0-hop neighbour
    SeedReport = 16, // node -> admin: progress of that relay session
};

enum class RelayState : uint8_t {
    Idle = 0,
    Starting = 1,
    Transferring = 2,
    Done = 3,
    Verified = 4,
    Failed = 5,
    Aborted = 6,
    Timeout = 7,
    Denied = 8,
    NoImage = 9,
    Cancelled = 10,
    Busy = 11,
};

class LoraOtaModule : public SinglePortModule, private concurrency::OSThread, private ota_common::IFrameOut
{
  public:
    LoraOtaModule();
    ~LoraOtaModule(); // out of line: Verify is incomplete here

  protected:
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    int32_t runOnce() override;

  private:
    enum class Phase : uint8_t { Idle = 0, Receiving = 1, Verifying = 2, Ready = 3, Failed = 4 };

    struct Relay {
        NodeNum target = 0;
        uint8_t channel = 0;
        uint8_t session = 0;
        NodeNum commander = 0;
        uint8_t commanderChannel = 0;
        RelayState state = RelayState::Idle;
        std::vector<ota_common::Hash256> leaves;
        std::vector<bool> acked;
        uint16_t ackedCount = 0;
        uint8_t targetPhase = 0xFF;
        uint8_t targetReject = 0;
        uint8_t lastReportDecile = 0;
        uint32_t startedMs = 0;
        uint32_t lastStartMs = 0;
        uint32_t lastRxMs = 0;
        uint32_t lastQueryMs = 0;
        uint32_t doneMs = 0;
    };

    void send_frame(const uint8_t *data, size_t len) override;
    void sendTo(NodeNum to, uint8_t channel, const uint8_t *data, size_t len, bool zeroHop);
    void sendSimple(NodeNum to, uint8_t channel, uint8_t type, uint8_t session, uint16_t index, bool zeroHop);
    void startSession(const meshtastic_MeshPacket &mp, uint8_t session);
    void endSession();
    void afterFrame();
    void captureManifest(const ota_common::OtaFrameHeader &h, const uint8_t *p, size_t n);
    void sendStatus(NodeNum to, uint8_t channel);
    struct Verify;
    bool verifyStep();
    bool consumeOutput(Verify &v, const ota_common::Manifest &m, size_t n);
    void loadAdminKeys();
    bool isAdminCommand(const meshtastic_MeshPacket &mp) const;

    void handleSeedTo(const meshtastic_MeshPacket &mp, const uint8_t *p, size_t n);
    void relayFrame(const ota_common::OtaFrameHeader &h, const uint8_t *p, size_t n);
    void relaySendUnit(uint8_t type, uint16_t index, const uint8_t *data, size_t len);
    void relayTick();
    void relayFinish(RelayState s);
    void relayReport(bool force);
    void sendSeedReport(NodeNum to, uint8_t channel, NodeNum target, RelayState state, uint8_t targetPhase, uint16_t acked,
                        uint16_t total, uint8_t reject, uint8_t session);
    bool relayActive() const;

    lora_ota::OtaStaging staging;
    ota_common::AdminKeyVerifier verifier;
    std::unique_ptr<ota_common::OtaReceiver> rx;
    Phase phase = Phase::Idle;
    uint8_t lastReject = 0;
    NodeNum seeder = 0;
    uint8_t seederChannel = 0;
    uint8_t sessionId = 0;
    uint32_t lastFrameMs = 0;
    uint32_t lastPollMs = 0;
    uint32_t frameGapMs = 2000;
    uint8_t manifestBuf[256];
    uint16_t manifestFill = 0;

    std::unique_ptr<Verify> verify;
    Relay relay;
};

extern LoraOtaModule *loraOtaModule;

#endif
