#include "LoraOtaModule.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "MeshService.h"
#include "NodeDB.h"
#include "OtaUnxz.h"
#include "mesh/Throttle.h"
#include "ota_common/sha256.h"
#include <algorithm>
#include <cstring>

LoraOtaModule *loraOtaModule;

using namespace lora_ota;
using ota_common::OtaFrameHeader;
using ota_common::OtaFrameType;

namespace
{
constexpr uint32_t POLL_MIN_MS = 3 * 1000;
constexpr uint32_t POLL_MAX_MS = 30 * 1000;
constexpr uint32_t GAP_INITIAL_MS = 2000;
constexpr uint32_t SESSION_IDLE_MS = 10 * 60 * 1000;
constexpr size_t VERIFY_IN_STEP = 8 * 1024;
constexpr uint8_t STATUS_VERSION = 1;

void putLe16(uint8_t *p, uint16_t v)
{
    p[0] = v;
    p[1] = v >> 8;
}
void putLe32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        p[i] = v >> (8 * i);
}
} // namespace

struct LoraOtaModule::Verify {
    ota_unxz *dec = nullptr;
    ota_common::Sha256 sha;
    size_t inPos = 0;
    uint32_t outLen = 0;
    bool vectorsChecked = false;
    uint8_t out[1024];
    ~Verify() { ota_unxz_destroy(dec); }
};

LoraOtaModule::~LoraOtaModule() = default;

LoraOtaModule::LoraOtaModule() : SinglePortModule("loraota", meshtastic_PortNum_LORA_OTA_APP), concurrency::OSThread("LoraOta")
{
    staging.load();
    switch (staging.state()) {
    case StagingState::Ready:
        phase = Phase::Ready;
        break;
    case StagingState::Received:
        phase = Phase::Verifying; // rebooted mid-verify
        break;
    default:
        break;
    }
    loadAdminKeys();
    LOG_INFO("LoRa OTA: app 0x%x-0x%x, staging state %u", appStart(), imageEnd(), (unsigned)staging.state());
}

void LoraOtaModule::loadAdminKeys()
{
    verifier = ota_common::AdminKeyVerifier();
    for (pb_size_t i = 0; i < config.security.admin_key_count; i++) {
        if (config.security.admin_key[i].size == 32)
            verifier.add_key(config.security.admin_key[i].bytes);
    }
}

void LoraOtaModule::sendTo(NodeNum to, uint8_t channel, const uint8_t *data, size_t len, bool zeroHop)
{
    meshtastic_MeshPacket *p = allocDataPacket();
    if (!p)
        return;
    if (len > sizeof(p->decoded.payload.bytes)) {
        packetPool.release(p);
        return;
    }
    p->to = to;
    p->channel = channel;
    if (zeroHop)
        p->hop_limit = 0; // bulk transfer frames never flood
    p->want_ack = false;
    p->decoded.payload.size = len;
    memcpy(p->decoded.payload.bytes, data, len);
    service->sendToMesh(p);
}

void LoraOtaModule::sendSimple(NodeNum to, uint8_t channel, uint8_t type, uint8_t session, uint16_t index, bool zeroHop)
{
    OtaFrameHeader h{static_cast<OtaFrameType>(type), session, index, 0, 0};
    uint8_t f[ota_common::kFrameHeaderLen];
    ota_common::frame_header_pack(h, f);
    sendTo(to, channel, f, sizeof(f), zeroHop);
}

void LoraOtaModule::send_frame(const uint8_t *data, size_t len)
{
    sendTo(seeder, seederChannel, data, len, true);
}

bool LoraOtaModule::isAdminCommand(const meshtastic_MeshPacket &mp) const
{
    if (!mp.pki_encrypted || mp.public_key.size != 32)
        return false;
    for (pb_size_t i = 0; i < config.security.admin_key_count; i++) {
        const auto &k = config.security.admin_key[i];
        if (k.size == 32 && memcmp(k.bytes, mp.public_key.bytes, 32) == 0)
            return true;
    }
    return false;
}

void LoraOtaModule::sendStatus(NodeNum to, uint8_t channel)
{
    uint8_t b[ota_common::kFrameHeaderLen + 116] = {0};
    OtaFrameHeader h{static_cast<OtaFrameType>(LoraOtaExtFrame::Status), sessionId, 0, 0, 0};
    ota_common::frame_header_pack(h, b);
    uint8_t *p = b + ota_common::kFrameHeaderLen;
    const ota_common::Manifest &m = staging.manifest();
    p[0] = STATUS_VERSION;
    p[1] = static_cast<uint8_t>(phase);
    p[2] = static_cast<uint8_t>(staging.state());
    p[3] = lastReject;
    putLe16(p + 4, staging.persistedCount());
    putLe16(p + 6, staging.hasManifest() ? m.block_count : 0);
    putLe32(p + 8, imageEnd());
    putLe32(p + 12, OTA_META_ADDR);
    loadAdminKeys(); // keys may have changed via admin since boot
    p[16] = verifier.key_count();
    p[17] = config.security.admin_key_count;
    // p[18..23]: reserved
    if (staging.hasManifest())
        memcpy(p + 24, m.output_sha256, 8);
    strncpy(reinterpret_cast<char *>(p + 32), optstr(APP_ENV), 32);
    strncpy(reinterpret_cast<char *>(p + 64), optstr(APP_VERSION), 48);
    putLe32(p + 112, appStart()); // lets the panel check that a package fits before sending it
    sendTo(to, channel, b, sizeof(b), false);
}

void LoraOtaModule::startSession(const meshtastic_MeshPacket &mp, uint8_t session)
{
    loadAdminKeys();
    rx.reset();
    verify.reset();
    seeder = mp.from;
    seederChannel = mp.channel;
    sessionId = session;
    lastReject = 0;
    frameGapMs = GAP_INITIAL_MS;
    rx.reset(new ota_common::OtaReceiver(staging, *this, session, &verifier));
    staging.attach(rx.get());
    phase = Phase::Receiving;
    LOG_INFO("LoRa OTA: session 0x%x from 0x%08x (%u admin keys)", session, seeder, (unsigned)verifier.key_count());
}

void LoraOtaModule::endSession()
{
    staging.detach();
    rx.reset();
    if (phase == Phase::Receiving)
        phase = Phase::Idle;
}

void LoraOtaModule::afterFrame()
{
    if (staging.rejected() != Reject::None) {
        lastReject = static_cast<uint8_t>(staging.rejected());
        LOG_WARN("LoRa OTA: manifest rejected (%u)", lastReject);
        sendSimple(seeder, seederChannel, static_cast<uint8_t>(OtaFrameType::Abort), sessionId, 0, true);
        endSession();
        return;
    }
    if (rx->aborted()) {
        LOG_WARN("LoRa OTA: session aborted (bad signature or geometry)");
        lastReject = static_cast<uint8_t>(Reject::BadSignature);
        sendSimple(seeder, seederChannel, static_cast<uint8_t>(OtaFrameType::Abort), sessionId, 0, true);
        endSession();
        return;
    }
    if (rx->complete()) {
        LOG_INFO("LoRa OTA: all %u blocks received", (unsigned)rx->blocks_total());
        staging.flush();
        endSession();
        phase = Phase::Verifying;
        setIntervalFromNow(0);
    }
}

ProcessMessage LoraOtaModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (isFromUs(&mp))
        return ProcessMessage::STOP;
    OtaFrameHeader h;
    const uint8_t *data = mp.decoded.payload.bytes;
    size_t len = mp.decoded.payload.size;
    if (!ota_common::frame_header_unpack(data, len, h))
        return ProcessMessage::STOP;
    const uint8_t *body = data + ota_common::kFrameHeaderLen;
    size_t bodyLen = len - ota_common::kFrameHeaderLen;
    uint8_t type = static_cast<uint8_t>(h.type);

    if (type == static_cast<uint8_t>(LoraOtaExtFrame::Query)) {
        sendStatus(mp.from, mp.channel);
        return ProcessMessage::STOP;
    }

    bool sessionLive = rx && Throttle::isWithinTimespanMs(lastFrameMs, SESSION_IDLE_MS);
    if (h.type == OtaFrameType::Start) {
        if (phase == Phase::Verifying)
            return ProcessMessage::STOP; // the staged image is in use
        if (sessionLive && mp.from != seeder)
            return ProcessMessage::STOP; // busy with another seeder
        if (!rx || mp.from != seeder || h.session != sessionId)
            startSession(mp, h.session);
    }
    if (!rx || mp.from != seeder)
        return ProcessMessage::STOP;

    uint32_t now = millis();
    uint32_t gap = now - lastFrameMs;
    if (gap < POLL_MAX_MS) // learn the seeder's frame pacing; a lost fragment is re-requested after a few gaps
        frameGapMs = (frameGapMs * 4 + gap) / 5;
    lastFrameMs = lastPollMs = now;
    rx->on_frame(data, len);
    afterFrame();
    return ProcessMessage::STOP;
}

bool LoraOtaModule::consumeOutput(Verify &v, const ota_common::Manifest &m, size_t n)
{
    if (!v.vectorsChecked) {
        uint32_t sp, reset;
        memcpy(&sp, v.out, 4);
        memcpy(&reset, v.out + 4, 4);
        if ((sp & 0xFFF00000) != 0x20000000 || reset < appStart() || reset >= appStart() + m.output_length) {
            LOG_ERROR("LoRa OTA: image vector table is not an app at 0x%x", appStart());
            return false;
        }
        v.vectorsChecked = true;
    }
    v.outLen += n;
    if (v.outLen > m.output_length)
        return false;
    v.sha.update(v.out, n);
    return true;
}

bool LoraOtaModule::verifyStep()
{
    const ota_common::Manifest &m = staging.manifest();
    if (!verify) {
        verify.reset(new Verify());
        verify->dec = ota_unxz_create(m.reserved0 & 0xFF, (m.flags & FLAG_ARMTHUMB) != 0);
        if (!verify->dec) {
            LOG_ERROR("LoRa OTA: no RAM for the LZMA decoder");
            return false;
        }
    }
    Verify &v = *verify;
    const uint8_t *in = reinterpret_cast<const uint8_t *>(staging.stagingStart());
    size_t inEnd = v.inPos + VERIFY_IN_STEP;
    if (inEnd > m.payload_length)
        inEnd = m.payload_length;

    ota_unxz_ret r;
    for (;;) {
        size_t outPos = 0;
        r = ota_unxz_run(v.dec, in, &v.inPos, inEnd, v.out, &outPos, sizeof(v.out));
        if (outPos && !consumeOutput(v, m, outPos))
            return false;
        if (r != OTA_UNXZ_OK || (outPos < sizeof(v.out) && v.inPos >= inEnd))
            break;
    }
    if (r == OTA_UNXZ_OK)
        return v.inPos < m.payload_length; // more input next round, or truncated stream
    if (r != OTA_UNXZ_END)
        return false;

    uint8_t digest[ota_common::kSha256Len];
    v.sha.finish(digest);
    bool ok = v.outLen == m.output_length && memcmp(digest, m.output_sha256, sizeof(digest)) == 0;
    verify.reset();
    staging.setState(ok ? StagingState::Ready : StagingState::Failed);
    phase = ok ? Phase::Ready : Phase::Failed;
    LOG_INFO("LoRa OTA: verification %s", ok ? "passed, image ready" : "FAILED");
    if (seeder)
        sendStatus(seeder, seederChannel);
    return true;
}

int32_t LoraOtaModule::runOnce()
{
    if (phase == Phase::Verifying) {
        if (!verifyStep()) {
            verify.reset();
            staging.setState(StagingState::Failed);
            phase = Phase::Failed;
            LOG_WARN("LoRa OTA: verification FAILED");
            if (seeder)
                sendStatus(seeder, seederChannel);
            return 1000;
        }
        return phase == Phase::Verifying ? 0 : 1000;
    }
    if (rx) {
        if (Throttle::hasElapsed(lastFrameMs, SESSION_IDLE_MS)) {
            LOG_INFO("LoRa OTA: session idle, progress kept (%u/%u)", (unsigned)rx->blocks_have(),
                     (unsigned)rx->blocks_total());
            endSession();
        } else if (Throttle::hasElapsed(lastPollMs, std::min(POLL_MAX_MS, std::max(POLL_MIN_MS, 4 * frameGapMs)))) {
            lastPollMs = millis();
            rx->poll();
        }
    }
    return 1000;
}

#endif
