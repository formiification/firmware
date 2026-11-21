#pragma once
// LoRa OTA staging in internal flash: the LZMA payload sits top-aligned below the meta page so the
// image decompressed into appStart() never overwrites what it is read from.

#include "configuration.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "ota_common/manifest.h"
#include "ota_common/transport.h"
#include <stddef.h>
#include <stdint.h>

namespace lora_ota
{

constexpr uint32_t OTA_META_ADDR = 0xE9000;
constexpr uint32_t OTA_PAGE = 4096;

// Fork manifest flags (bit0 = delta in ota-common); reserved0 low byte = LZMA2 dictionary property.
constexpr uint16_t FLAG_LZMA2 = 0x0002;
constexpr uint16_t FLAG_ARMTHUMB = 0x0004;

enum class StagingState : uint32_t {
    Empty = 0,
    Receiving = 1,
    Received = 2, // all blocks merkle-verified and stored
    Ready = 3,    // decompressed image matches output_sha256
    Failed = 4,
    Installed = 5, // written over the application by OtaInstall; still seedable
};

enum class Reject : uint8_t {
    None = 0,
    NotFullLzma = 1,
    WrongEnv = 2,
    TooBig = 3,
    Geometry = 4,
    BadSignature = 5, // set by the module: OtaReceiver aborted on the manifest
};

uint32_t appStart(); // ORIGIN(FLASH): 0x26000 with S140 v6, 0x27000 with v7
uint32_t imageEnd();
inline uint32_t alignUp(uint32_t v)
{
    return (v + OTA_PAGE - 1) & ~(OTA_PAGE - 1);
}

class OtaStaging final : public ota_common::IBlockStore
{
  public:
    void load();
    void attach(const ota_common::OtaReceiver *rx);
    void detach() { rx_ = nullptr; }

    bool has_block(uint32_t index) const override;
    bool put_block(uint32_t index, const uint8_t *data, uint32_t len) override;
    uint32_t stored_count() const override { return bound_ ? done_ : 0; }
    uint32_t persistedCount() const { return bound_ ? done_ : (meta_.magic == META_MAGIC ? meta_.done : 0); }

    Reject rejected() const { return reject_; }
    StagingState state() const { return meta_.state; }
    const ota_common::Manifest &manifest() const { return meta_.manifest; }
    const uint8_t *signature() const { return meta_.signature; }
    void setSignature(const uint8_t *sig);
    bool seedable() const
    {
        return meta_.magic == META_MAGIC && (meta_.state == StagingState::Ready || meta_.state == StagingState::Installed);
    }
    bool hasManifest() const { return meta_.magic == META_MAGIC; }
    uint32_t stagingStart() const { return OTA_META_ADDR - alignUp(meta_.manifest.payload_length); }

    void setState(StagingState s);
    void flush();

    static Reject check(const ota_common::Manifest &m);

  private:
    static constexpr uint32_t META_MAGIC = 0x4D544F4C; // "LOTM"
    static constexpr uint32_t META_VERSION = 2;
    static constexpr uint32_t FLUSH_EVERY = 16;

    struct Meta {
        uint32_t magic;
        uint32_t version;
        StagingState state;
        uint32_t done; // contiguous blocks stored from 0
        ota_common::Manifest manifest;
        uint8_t signature[64]; // kept so this node can re-seed the image to its neighbours
        uint32_t crc;
    };

  public:
    static constexpr size_t META_STATE_OFFSET = 8; // Meta::state, checked below
    static constexpr size_t META_CRC_OFFSET = 16 + sizeof(ota_common::Manifest) + 64;

  private:
    bool ensureBound() const;
    void writeMeta();
    static uint32_t crc32(const uint8_t *p, size_t n);

    const ota_common::OtaReceiver *rx_ = nullptr;
    mutable bool bound_ = false;
    mutable uint32_t done_ = 0;
    mutable Reject reject_ = Reject::None;
    mutable bool metaDirty_ = false;
    mutable Meta meta_{};
    static_assert(offsetof(Meta, state) == META_STATE_OFFSET, "OtaInstall patches Meta::state in place");
    static_assert(offsetof(Meta, crc) == META_CRC_OFFSET, "OtaInstall recomputes Meta::crc in place");
};

} // namespace lora_ota

#endif
