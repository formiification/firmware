#include "LoraOtaModule.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "MeshService.h"
#include "NodeDB.h"
#include "OtaInstall.h"
#include "OtaUnxz.h"
#include "UptimeClock.h"
#include "main.h"
#include "airtime.h"
#include "modules/NodeInfoModule.h"
#include "RadioLibInterface.h"
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
constexpr uint8_t STATUS_VERSION = 2; // 2: via + via SNR at 116
constexpr size_t STATUS_LEN = 121;
constexpr uint32_t NEIGHBOR_QUERY_INTERVAL_MS = 30 * 1000;
constexpr uint32_t STATUS_JITTER_MIN_MS = 300;
constexpr uint32_t STATUS_JITTER_MAX_MS = 4000;
constexpr size_t FRAGMENT = 200; // leaves room for PKI overhead under the 233-byte payload cap
constexpr uint32_t RELAY_START_RETRY_MS = 60 * 1000;
constexpr uint32_t RELAY_SILENCE_MS = 15 * 60 * 1000;
constexpr uint32_t RELAY_VERIFY_WAIT_MS = 5 * 60 * 1000;
constexpr uint32_t KEY_REQUEST_INTERVAL_MS = 60 * 1000;
// A relay paces its frames to this share of airtime, under the firmware's polite limit (half the region's
// duty cycle, 5 % in EU868): unpaced it answers every request at once and then stalls for most of an hour.
constexpr uint32_t RELAY_DUTY_PERCENT = 4;
constexpr uint32_t PACKET_OVERHEAD = 16 + 12 + 6; // header, PKI tag/nonce, Data protobuf around our payload
constexpr uint32_t INSTALL_REBOOT_DELAY_MS = 3000; // lets the Installing status leave the radio
const char ACTIVATE_TAG[] = "LOTA-ACTIVATE";

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

// Our replies are DMs, and the router refuses a DM to a node whose public key it lacks (only traceroute,
// NodeInfo, position and routing are exempt). Swap NodeInfo so the peer's next retry gets an answer.
void LoraOtaModule::requestKey(NodeNum peer, uint8_t channel)
{
#if !MESHTASTIC_EXCLUDE_PKI
    meshtastic_NodeInfoLite_public_key_t key;
    if (!nodeInfoModule || isBroadcast(peer) || nodeDB->copyPublicKey(peer, key))
        return;
    if (peer == keyAsked && Throttle::isWithinTimespanMs(keyAskedMs, KEY_REQUEST_INTERVAL_MS))
        return;
    keyAsked = peer;
    keyAskedMs = millis();
    LOG_INFO("LoRa OTA: no public key for 0x%08x, requesting its NodeInfo", peer);
    // Short timeout: the routine path skips a NodeInfo sent in the last ~30 min, e.g. the one sent at boot.
    nodeInfoModule->sendOurNodeInfo(peer, true, channel, true);
#else
    (void)peer;
    (void)channel;
#endif
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

void LoraOtaModule::sendStatus(NodeNum to, uint8_t channel, NodeNum via, int8_t viaSnrQ)
{
    uint8_t b[ota_common::kFrameHeaderLen + STATUS_LEN] = {0};
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
    p[18] = static_cast<uint8_t>(relay.state);
    p[19] = relay.targetPhase;
    putLe32(p + 20, relay.target);
    if (staging.hasManifest())
        memcpy(p + 24, m.output_sha256, 8);
    strncpy(reinterpret_cast<char *>(p + 32), optstr(APP_ENV), 32);
    strncpy(reinterpret_cast<char *>(p + 64), optstr(APP_VERSION), 48);
    putLe32(p + 112, appStart()); // lets the panel check that a package fits before sending it
    putLe32(p + 116, via);        // node whose 0-hop Query we answer (a remote neighbour query), else 0
    p[120] = static_cast<uint8_t>(viaSnrQ); // SNR of that Query here, dB * 4
    sendTo(to, channel, b, sizeof(b), false);
}

void LoraOtaModule::handleQuery(const meshtastic_MeshPacket &mp, const uint8_t *p, size_t n)
{
    NodeNum to = mp.from, via = 0;
    int8_t snrQ = 0;
    if (n >= 4) { // relayed neighbour query: answer the node that asked for it, say whose broadcast we heard
        NodeNum replyTo = (NodeNum)p[0] | (NodeNum)p[1] << 8 | (NodeNum)p[2] << 16 | (NodeNum)p[3] << 24;
        if (replyTo && replyTo != nodeDB->getNodeNum()) {
            to = replyTo;
            via = mp.from;
            float q = mp.rx_snr * 4;
            snrQ = static_cast<int8_t>(q > 127 ? 127 : q < -128 ? -128 : q);
            requestKey(to, mp.channel);
        }
    }
    if (!isBroadcast(mp.to)) {
        sendStatus(to, mp.channel, via, snrQ);
        return;
    }
    pendingStatus = {to, mp.channel, via, snrQ, millis(), (uint32_t)random(STATUS_JITTER_MIN_MS, STATUS_JITTER_MAX_MS)};
    setIntervalFromNow(pendingStatus.delayMs);
}

void LoraOtaModule::handleQueryNeighbors(const meshtastic_MeshPacket &mp, const uint8_t *p, size_t n)
{
    if (!isAdminCommand(mp)) {
        LOG_WARN("LoRa OTA: QueryNeighbors from 0x%08x refused (not an admin key over PKI)", mp.from);
        return;
    }
    if (lastNeighborQueryMs && Throttle::isWithinTimespanMs(lastNeighborQueryMs, NEIGHBOR_QUERY_INTERVAL_MS))
        return;
    lastNeighborQueryMs = millis();
    NodeNum replyTo = n >= 4 ? (NodeNum)p[0] | (NodeNum)p[1] << 8 | (NodeNum)p[2] << 16 | (NodeNum)p[3] << 24 : mp.from;
    uint8_t f[ota_common::kFrameHeaderLen + 4];
    OtaFrameHeader h{static_cast<OtaFrameType>(LoraOtaExtFrame::Query), 0, 0, 0, 0};
    ota_common::frame_header_pack(h, f);
    putLe32(f + ota_common::kFrameHeaderLen, replyTo);
    LOG_INFO("LoRa OTA: neighbour query for 0x%08x", replyTo);
    sendTo(NODENUM_BROADCAST, mp.channel, f, sizeof(f), true);
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

void LoraOtaModule::captureManifest(const OtaFrameHeader &h, const uint8_t *p, size_t n)
{
    // OtaReceiver keeps only the manifest; the signature is needed to re-seed this image later.
    if (h.total != sizeof(manifestBuf) || h.off != manifestFill || h.off + n > sizeof(manifestBuf)) {
        if (h.off == 0 && h.total == sizeof(manifestBuf) && n <= sizeof(manifestBuf)) {
            manifestFill = 0;
        } else {
            return;
        }
    }
    memcpy(manifestBuf + manifestFill, p, n);
    manifestFill += n;
}

void LoraOtaModule::afterFrame()
{
    if (rx->manifest_ready() && manifestFill == sizeof(manifestBuf) &&
        memcmp(manifestBuf, &rx->manifest(), sizeof(ota_common::Manifest)) == 0)
        staging.setSignature(manifestBuf + sizeof(ota_common::Manifest));
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
    requestKey(mp.from, mp.channel);

    if (type == static_cast<uint8_t>(LoraOtaExtFrame::Query)) {
        handleQuery(mp, body, bodyLen);
        return ProcessMessage::STOP;
    }
    if (type == static_cast<uint8_t>(LoraOtaExtFrame::QueryNeighbors)) {
        handleQueryNeighbors(mp, body, bodyLen);
        return ProcessMessage::STOP;
    }
    if (type == static_cast<uint8_t>(LoraOtaExtFrame::SeedTo)) {
        handleSeedTo(mp, body, bodyLen);
        return ProcessMessage::STOP;
    }
    if (type == static_cast<uint8_t>(LoraOtaExtFrame::Activate)) {
        handleActivate(mp, body, bodyLen);
        return ProcessMessage::STOP;
    }
    if (relayActive() && mp.from == relay.target) {
        relayFrame(h, body, bodyLen);
        return ProcessMessage::STOP;
    }

    bool sessionLive = rx && Throttle::isWithinTimespanMs(lastFrameMs, SESSION_IDLE_MS);
    if (h.type == OtaFrameType::Start) {
        if (phase == Phase::Verifying || relayActive())
            return ProcessMessage::STOP; // the staged image is in use
        if (sessionLive && mp.from != seeder)
            return ProcessMessage::STOP; // busy with another seeder
        if (!rx || mp.from != seeder || h.session != sessionId) {
            startSession(mp, h.session);
            manifestFill = 0;
        }
    }
    if (!rx || mp.from != seeder)
        return ProcessMessage::STOP;

    uint32_t now = millis();
    uint32_t gap = now - lastFrameMs;
    if (gap < POLL_MAX_MS) // learn the seeder's frame pacing; a lost fragment is re-requested after a few gaps
        frameGapMs = (frameGapMs * 4 + gap) / 5;
    lastFrameMs = lastPollMs = now;
    if (h.type == OtaFrameType::Manifest)
        captureManifest(h, body, bodyLen);
    rx->on_frame(data, len);
    afterFrame();
    return ProcessMessage::STOP;
}

void LoraOtaModule::handleActivate(const meshtastic_MeshPacket &mp, const uint8_t *p, size_t n)
{
    const ota_common::Manifest &m = staging.manifest();
    bool ready = phase != Phase::Installing && !rx && !relayActive() && staging.state() == StagingState::Ready;
    bool imageMatches = n >= 32 && staging.hasManifest() && memcmp(p, m.output_sha256, 32) == 0;
    bool authorized = isAdminCommand(mp);
    if (!authorized && n >= 32 + 64) {
        uint8_t msg[sizeof(ACTIVATE_TAG) - 1 + 32];
        memcpy(msg, ACTIVATE_TAG, sizeof(ACTIVATE_TAG) - 1);
        memcpy(msg + sizeof(ACTIVATE_TAG) - 1, p, 32);
        loadAdminKeys();
        authorized = verifier.verify(msg, sizeof(msg), p + 32, 64);
    }
    if (!ready || !imageMatches || !authorized) {
        LOG_WARN("LoRa OTA: Activate from 0x%08x refused (ready=%d image=%d auth=%d)", mp.from, ready, imageMatches, authorized);
        sendStatus(mp.from, mp.channel);
        return;
    }
    LOG_INFO("LoRa OTA: installing staged image on reboot (requested by 0x%08x)", mp.from);
    staging.flush();
    phase = Phase::Installing;
    sendStatus(mp.from, mp.channel);
    requestInstall();
    rebootAtMsec = Time::timerEndsAtMillis(INSTALL_REBOOT_DELAY_MS);
}

bool LoraOtaModule::relayActive() const
{
    return relay.state == RelayState::Starting || relay.state == RelayState::Transferring ||
           relay.state == RelayState::Done;
}

void LoraOtaModule::handleSeedTo(const meshtastic_MeshPacket &mp, const uint8_t *p, size_t n)
{
    NodeNum target = n >= 4 ? (NodeNum)p[0] | (NodeNum)p[1] << 8 | (NodeNum)p[2] << 16 | (NodeNum)p[3] << 24 : 0;
    uint8_t channel = n >= 5 ? p[4] : 0;
    RelayState refusal = RelayState::Idle;
    if (!isAdminCommand(mp))
        refusal = RelayState::Denied;
    else if (target == 0) {
        if (relayActive())
            relayFinish(RelayState::Cancelled);
        return;
    } else if (relayActive() && target == relay.target) {
        relay.commander = mp.from;
        relay.commanderChannel = mp.channel;
        relayReport(true);
        return;
    } else if (relayActive() || rx || phase == Phase::Verifying)
        refusal = RelayState::Busy;
    else if (!staging.seedable() || target == nodeDB->getNodeNum())
        refusal = RelayState::NoImage;
    if (refusal != RelayState::Idle) {
        LOG_WARN("LoRa OTA: SeedTo 0x%08x from 0x%08x refused (%u)", target, mp.from, (unsigned)refusal);
        sendSeedReport(mp.from, mp.channel, target, refusal, 0xFF, 0, 0, 0, 0);
        return;
    }
    relay.commander = mp.from;
    relay.commanderChannel = mp.channel;
    const ota_common::Manifest &m = staging.manifest();
    relay.target = target;
    relay.channel = channel;
    relay.session = (uint8_t)random(1, 256);
    relay.leaves.clear();
    relay.leaves.reserve(m.block_count);
    const uint8_t *payload = reinterpret_cast<const uint8_t *>(staging.stagingStart());
    for (uint32_t off = 0; off < m.payload_length; off += m.block_size) {
        uint32_t blen = off + m.block_size <= m.payload_length ? m.block_size : m.payload_length - off;
        relay.leaves.push_back(ota_common::hash_leaf(payload + off, blen));
    }
    relay.acked.assign(m.block_count, false);
    relay.ackedCount = 0;
    relay.targetPhase = 0xFF;
    relay.targetReject = 0;
    relay.lastReportDecile = 0;
    relay.state = RelayState::Starting;
    relay.startedMs = relay.lastRxMs = millis();
    relay.paceGapMs = 0;
    relay.lastStartMs = 0;
    relay.doneMs = 0;
    requestKey(target, channel); // relay frames to the target are DMs too
    LOG_INFO("LoRa OTA: seeding staged image to 0x%08x for 0x%08x", target, mp.from);
    relayReport(true);
    setIntervalFromNow(0);
}

void LoraOtaModule::relaySendUnit(uint8_t type, uint16_t index, const uint8_t *data, size_t len)
{
    uint8_t f[ota_common::kFrameHeaderLen + FRAGMENT];
    if (len == 0) {
        sendSimple(relay.target, relay.channel, type, relay.session, index, true);
        return;
    }
    for (size_t off = 0; off < len; off += FRAGMENT) {
        size_t n = len - off < FRAGMENT ? len - off : FRAGMENT;
        OtaFrameHeader h{static_cast<OtaFrameType>(type), relay.session, index, (uint16_t)off, (uint16_t)len};
        ota_common::frame_header_pack(h, f);
        memcpy(f + ota_common::kFrameHeaderLen, data + off, n);
        sendTo(relay.target, relay.channel, f, ota_common::kFrameHeaderLen + n, true);
        if (RadioLibInterface::instance)
            relay.unitAirMs += RadioLibInterface::instance->getPacketTime(ota_common::kFrameHeaderLen + n + PACKET_OVERHEAD);
    }
}

void LoraOtaModule::relayFrame(const OtaFrameHeader &h, const uint8_t *p, size_t n)
{
    uint8_t type = static_cast<uint8_t>(h.type);
    if (type == static_cast<uint8_t>(LoraOtaExtFrame::Status)) {
        if (n >= 4) {
            relay.targetPhase = p[1];
            relay.targetReject = p[3];
            if (relay.state == RelayState::Done && (p[1] == 3 || p[1] == 4))
                relayFinish(p[1] == 3 ? RelayState::Verified : RelayState::Failed);
        }
        return;
    }
    if (h.session != relay.session)
        return;
    relay.lastRxMs = millis();
    const ota_common::Manifest &m = staging.manifest();
    switch (h.type) {
    case OtaFrameType::Request:
        if (relay.state == RelayState::Starting)
            relay.state = RelayState::Transferring;
        if (!airTime->isTxAllowedAirUtil()) {
            LOG_DEBUG("LoRa OTA: relay paused, airtime budget used"); // the target re-requests after its poll
            return;
        }
        if (relay.paceGapMs && Throttle::isWithinTimespanMs(relay.paceFromMs, relay.paceGapMs))
            return; // pacing: the target asks again after its poll interval
        relay.unitAirMs = 0;
        if (h.index == ota_common::kIndexManifest) {
            uint8_t unit[sizeof(ota_common::Manifest) + 64];
            memcpy(unit, &m, sizeof(m));
            memcpy(unit + sizeof(m), staging.signature(), 64);
            relaySendUnit(static_cast<uint8_t>(OtaFrameType::Manifest), h.index, unit, sizeof(unit));
        } else if (h.index < m.block_count) {
            std::vector<ota_common::Hash256> proof = ota_common::merkle_proof(relay.leaves, h.index);
            relaySendUnit(static_cast<uint8_t>(OtaFrameType::Proof), h.index, reinterpret_cast<const uint8_t *>(proof.data()),
                          proof.size() * sizeof(ota_common::Hash256));
            uint32_t off = (uint32_t)h.index * m.block_size;
            uint32_t blen = off + m.block_size <= m.payload_length ? m.block_size : m.payload_length - off;
            relaySendUnit(static_cast<uint8_t>(OtaFrameType::Block), h.index,
                          reinterpret_cast<const uint8_t *>(staging.stagingStart()) + off, blen);
        }
        relay.paceFromMs = millis();
        relay.paceGapMs = relay.unitAirMs * 100 / RELAY_DUTY_PERCENT;
        break;
    case OtaFrameType::Ack:
        if (h.index < relay.acked.size() && !relay.acked[h.index]) {
            relay.acked[h.index] = true;
            relay.ackedCount++;
            relayReport(false);
        }
        break;
    case OtaFrameType::Done:
        relay.ackedCount = m.block_count;
        relay.state = RelayState::Done;
        relay.doneMs = millis();
        relayReport(true);
        break;
    case OtaFrameType::Abort:
        relayFinish(RelayState::Aborted);
        break;
    default:
        break;
    }
}

void LoraOtaModule::relayTick()
{
    if (!relayActive())
        return;
    if (!airTime->isTxAllowedAirUtil()) {
        relay.lastRxMs = millis(); // our own pause: do not count it as target silence
        return;
    }
    if (relay.state == RelayState::Transferring && Throttle::hasElapsed(relay.lastRxMs, 60 * 1000) &&
        Throttle::hasElapsed(relay.lastStartMs, 60 * 1000)) {
        relay.state = RelayState::Starting; // target may have closed its idle session: re-kick, it resumes from flash
    }
    if (relay.state == RelayState::Starting && (relay.lastStartMs == 0 || Throttle::hasElapsed(relay.lastStartMs, RELAY_START_RETRY_MS))) {
        const ota_common::Manifest &m = staging.manifest();
        uint8_t f[ota_common::kFrameHeaderLen + 12];
        OtaFrameHeader h{OtaFrameType::Start, relay.session, 0, 0, 0};
        ota_common::frame_header_pack(h, f);
        uint8_t *b = f + ota_common::kFrameHeaderLen;
        putLe16(b, m.block_size);
        putLe16(b + 2, m.block_count);
        putLe32(b + 4, m.payload_length);
        putLe16(b + 8, sizeof(ota_common::Manifest));
        putLe16(b + 10, 64);
        sendTo(relay.target, relay.channel, f, sizeof(f), true);
        relay.lastStartMs = millis();
    }
    if (relay.state == RelayState::Done) {
        if (Throttle::hasElapsed(relay.doneMs, RELAY_VERIFY_WAIT_MS))
            return relayFinish(RelayState::Done); // verified state unknown; the panel can query the target
        if (Throttle::hasElapsed(relay.doneMs, 30 * 1000) &&
            (relay.lastQueryMs == 0 || Throttle::hasElapsed(relay.lastQueryMs, 60 * 1000))) {
            sendSimple(relay.target, relay.channel, static_cast<uint8_t>(LoraOtaExtFrame::Query), relay.session, 0, true);
            relay.lastQueryMs = millis();
        }
        return;
    }
    if (Throttle::hasElapsed(relay.lastRxMs, RELAY_SILENCE_MS))
        relayFinish(RelayState::Timeout);
}

void LoraOtaModule::relayFinish(RelayState s)
{
    if (s == RelayState::Cancelled || s == RelayState::Timeout)
        sendSimple(relay.target, relay.channel, static_cast<uint8_t>(OtaFrameType::Abort), relay.session, 0, true);
    relay.state = s;
    relay.leaves.clear();
    relay.leaves.shrink_to_fit();
    relay.acked.clear();
    relay.acked.shrink_to_fit();
    LOG_INFO("LoRa OTA: relay to 0x%08x finished (%u)", relay.target, (unsigned)s);
    relayReport(true);
}

void LoraOtaModule::sendSeedReport(NodeNum to, uint8_t channel, NodeNum target, RelayState state, uint8_t targetPhase,
                                   uint16_t acked, uint16_t total, uint8_t reject, uint8_t session)
{
    uint8_t f[ota_common::kFrameHeaderLen + 12];
    OtaFrameHeader h{static_cast<OtaFrameType>(LoraOtaExtFrame::SeedReport), session, 0, 0, 0};
    ota_common::frame_header_pack(h, f);
    uint8_t *b = f + ota_common::kFrameHeaderLen;
    putLe32(b, target);
    b[4] = static_cast<uint8_t>(state);
    b[5] = targetPhase;
    putLe16(b + 6, acked);
    putLe16(b + 8, total);
    b[10] = reject;
    b[11] = 0;
    sendTo(to, channel, f, sizeof(f), false);
}

void LoraOtaModule::relayReport(bool force)
{
    if (!relay.commander)
        return;
    const uint16_t total = staging.hasManifest() ? staging.manifest().block_count : 0;
    uint8_t decile = total ? (uint8_t)(relay.ackedCount * 10 / total) : 0;
    if (!force && decile == relay.lastReportDecile)
        return; // at most ~10 progress reports per session over the multi-hop path
    relay.lastReportDecile = decile;
    sendSeedReport(relay.commander, relay.commanderChannel, relay.target, relay.state, relay.targetPhase, relay.ackedCount,
                   total, relay.targetReject, relay.session);
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
    if (pendingStatus.to && !Throttle::isWithinTimespanMs(pendingStatus.setMs, pendingStatus.delayMs)) {
        PendingStatus s = pendingStatus;
        pendingStatus.to = 0;
        sendStatus(s.to, s.channel, s.via, s.viaSnrQ);
    }
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
    relayTick();
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
