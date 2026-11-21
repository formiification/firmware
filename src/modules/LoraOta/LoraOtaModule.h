#pragma once
#include "configuration.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "OtaStaging.h"
#include "SinglePortModule.h"
#include "concurrency/OSThread.h"
#include "ota_common/admin_key_verifier.h"
#include "ota_common/transport.h"
#include <memory>

// Fork frame types on LORA_OTA_APP, after ota-common's 1..11.
enum class LoraOtaExtFrame : uint8_t {
    Query = 12,      // any -> node: reply with Status
    Status = 13,     // node -> asker
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

    void send_frame(const uint8_t *data, size_t len) override;
    void sendTo(NodeNum to, uint8_t channel, const uint8_t *data, size_t len, bool zeroHop);
    void sendSimple(NodeNum to, uint8_t channel, uint8_t type, uint8_t session, uint16_t index, bool zeroHop);
    void startSession(const meshtastic_MeshPacket &mp, uint8_t session);
    void endSession();
    void afterFrame();
    void sendStatus(NodeNum to, uint8_t channel);
    struct Verify;
    bool verifyStep();
    bool consumeOutput(Verify &v, const ota_common::Manifest &m, size_t n);
    void loadAdminKeys();
    bool isAdminCommand(const meshtastic_MeshPacket &mp) const;

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

    std::unique_ptr<Verify> verify;
};

extern LoraOtaModule *loraOtaModule;

#endif
