#include "OtaStaging.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "FSCommon.h"
#include "SPILock.h"
#include "flash/flash_nrf5x.h"
#include <cstring>

extern "C" uint32_t __flash_arduino_start;
extern "C" uint32_t __etext;
extern "C" uint32_t __data_start__;
extern "C" uint32_t __data_end__;

namespace lora_ota
{

namespace
{
// spiLock first, then the LittleFS mutex guarding the shared flash_nrf5x cache (as WarmNodeStore).
struct FlashLock {
    concurrency::LockGuard spi{spiLock};
    FlashLock() { FSCom._lockFS(); }
    ~FlashLock() { FSCom._unlockFS(); }
};

bool strFieldEq(const char *field, size_t fieldLen, const char *s)
{
    size_t n = strnlen(field, fieldLen);
    return n == strlen(s) && memcmp(field, s, n) == 0;
}
} // namespace

uint32_t appStart()
{
    return (uint32_t)(uintptr_t)&__flash_arduino_start;
}

uint32_t imageEnd()
{
    return (uint32_t)(uintptr_t)&__etext + (uint32_t)((uintptr_t)&__data_end__ - (uintptr_t)&__data_start__);
}

uint32_t OtaStaging::crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

Reject OtaStaging::check(const ota_common::Manifest &m)
{
    if ((m.flags & ota_common::kManifestFlagDelta) || !(m.flags & FLAG_LZMA2))
        return Reject::NotFullLzma;
    if (!strFieldEq(m.env, sizeof(m.env), optstr(APP_ENV)))
        return Reject::WrongEnv;
    if (m.block_size == 0 || m.block_size > 4096 || m.block_count == 0 ||
        (uint64_t)m.block_size * m.block_count < m.payload_length ||
        (uint64_t)m.block_size * (m.block_count - 1) >= m.payload_length)
        return Reject::Geometry;
    if (m.payload_length >= OTA_META_ADDR - appStart())
        return Reject::TooBig;
    uint32_t start = OTA_META_ADDR - alignUp(m.payload_length);
    if (alignUp(imageEnd()) > start)
        return Reject::TooBig;
    if ((uint64_t)appStart() + m.output_length > start)
        return Reject::TooBig;
    return Reject::None;
}

void OtaStaging::load()
{
    memcpy(&meta_, (const void *)OTA_META_ADDR, sizeof(meta_));
    if (meta_.magic != META_MAGIC || meta_.version != META_VERSION ||
        meta_.crc != crc32((const uint8_t *)&meta_, offsetof(Meta, crc))) {
        memset(&meta_, 0, sizeof(meta_));
        return;
    }
    if (check(meta_.manifest) != Reject::None)
        memset(&meta_, 0, sizeof(meta_));
}

void OtaStaging::attach(const ota_common::OtaReceiver *rx)
{
    rx_ = rx;
    bound_ = false;
    done_ = 0;
    reject_ = Reject::None;
}

bool OtaStaging::ensureBound() const
{
    if (bound_)
        return true;
    if (!rx_ || !rx_->manifest_ready() || reject_ != Reject::None)
        return false;
    const ota_common::Manifest &m = rx_->manifest();
    if (meta_.magic == META_MAGIC && memcmp(&meta_.manifest, &m, sizeof(m)) == 0) {
        done_ = meta_.done;
        bound_ = true;
        return true;
    }
    reject_ = check(m);
    if (reject_ != Reject::None)
        return false;
    memset(&meta_, 0, sizeof(meta_));
    meta_.magic = META_MAGIC;
    meta_.version = META_VERSION;
    meta_.state = StagingState::Receiving;
    meta_.manifest = m;
    done_ = 0;
    bound_ = true;
    metaDirty_ = true;
    return true;
}

bool OtaStaging::has_block(uint32_t index) const
{
    return ensureBound() && index < done_;
}

bool OtaStaging::put_block(uint32_t index, const uint8_t *data, uint32_t len)
{
    if (!ensureBound())
        return false;
    if (index < done_)
        return true;
    const ota_common::Manifest &m = meta_.manifest;
    if (index != done_ || index >= m.block_count)
        return false; // receiver always asks for the lowest missing block
    uint32_t off = index * m.block_size;
    uint32_t expect = (off + m.block_size <= m.payload_length) ? m.block_size : m.payload_length - off;
    if (len != expect)
        return false;
    {
        FlashLock lock;
        if (flash_nrf5x_write(stagingStart() + off, data, len) < 0)
            return false;
    }
    done_++;
    meta_.done = done_;
    if (done_ == m.block_count)
        meta_.state = StagingState::Received;
    if (metaDirty_ || done_ % FLUSH_EVERY == 0 || done_ == m.block_count)
        writeMeta();
    return true;
}

void OtaStaging::setState(StagingState s)
{
    if (meta_.magic != META_MAGIC)
        return;
    meta_.state = s;
    if (s == StagingState::Failed) {
        meta_.done = 0;
        done_ = 0;
    }
    writeMeta();
}

void OtaStaging::flush()
{
    FlashLock lock;
    flash_nrf5x_flush();
}

void OtaStaging::writeMeta()
{
    meta_.crc = crc32((const uint8_t *)&meta_, offsetof(Meta, crc));
    FlashLock lock;
    flash_nrf5x_flush(); // staged blocks hit flash before the progress that claims them
    flash_nrf5x_write(OTA_META_ADDR, &meta_, sizeof(meta_));
    flash_nrf5x_flush();
    metaDirty_ = false;
}

} // namespace lora_ota

#endif
