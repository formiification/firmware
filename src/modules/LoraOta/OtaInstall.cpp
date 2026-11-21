#include "OtaInstall.h"

#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA && defined(NRF52840_XXAA)

#include "OtaStaging.h"
#include "OtaUnxz.h"
#include <cstring>

#if !defined(OTA_HOST_EMU)
#include "nrf.h"
#include "nrf_sdm.h"
#include "nrf_soc.h"
#define OTA_RAMFUNC __attribute__((section(".data.ota_ramfunc"), noinline, optimize("no-tree-loop-distribute-patterns")))
#else
#define OTA_RAMFUNC
#endif

namespace lora_ota
{

namespace
{
constexpr uint32_t PAGE_WORDS = OTA_PAGE / 4;
constexpr uint16_t BANK_VALID_APP = 0x01;
constexpr uint16_t BANK_INVALID_APP = 0xFF;

// OTAFIX bootloader_settings_t (sdk11 bootloader_types.h), at the start of BL_SETTINGS_ADDR.
struct BlSettings {
    uint16_t bank0;
    uint16_t bank0Crc; // 0 = the bootloader does not check the CRC
    uint16_t bank1;
    uint16_t pad;
    uint32_t bank0Size;
    uint32_t sdImageSize;
    uint32_t blImageSize;
    uint32_t appImageSize;
    uint32_t sdImageStart;
};
static_assert(sizeof(BlSettings) == 28, "bootloader settings layout");

struct InstallCtx {
    ota_unxz *dec;
    const uint8_t *in;
    size_t inLen;
    uint32_t appStart;
    uint32_t outLen;
    uint32_t metaAddr;
};

// Everything below runs after the application flash starts being erased: RAM only, no flash calls.
alignas(4) uint32_t pageBuf[PAGE_WORDS];

OTA_RAMFUNC void ramCopyFromFlash(uint32_t addr)
{
    const volatile uint32_t *src = reinterpret_cast<const volatile uint32_t *>(addr);
    for (uint32_t i = 0; i < PAGE_WORDS; i++)
        pageBuf[i] = src[i];
}

OTA_RAMFUNC void ramWritePage(uint32_t addr)
{
    hw::nvmcErase(addr);
    hw::nvmcWrite(addr, pageBuf, PAGE_WORDS);
    hw::watchdogFeed();
}

OTA_RAMFUNC void ramSetBank0(uint16_t bank0, uint32_t size)
{
    ramCopyFromFlash(BL_SETTINGS_ADDR);
    BlSettings *s = reinterpret_cast<BlSettings *>(pageBuf);
    s->bank0 = bank0;
    s->bank0Crc = 0;
    s->bank1 = BANK_INVALID_APP;
    if (bank0 == BANK_VALID_APP) {
        s->bank0Size = size;
        s->sdImageSize = s->blImageSize = s->appImageSize = s->sdImageStart = 0;
    }
    ramWritePage(BL_SETTINGS_ADDR);
}

OTA_RAMFUNC uint32_t ramCrc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

OTA_RAMFUNC void ramMarkInstalled(uint32_t metaAddr)
{
    ramCopyFromFlash(metaAddr);
    uint8_t *m = reinterpret_cast<uint8_t *>(pageBuf);
    const uint32_t installed = static_cast<uint32_t>(StagingState::Installed);
    for (int i = 0; i < 4; i++)
        m[OtaStaging::META_STATE_OFFSET + i] = (installed >> (8 * i)) & 0xFF;
    const uint32_t crc = ramCrc32(m, OtaStaging::META_CRC_OFFSET);
    for (int i = 0; i < 4; i++)
        m[OtaStaging::META_CRC_OFFSET + i] = (crc >> (8 * i)) & 0xFF;
    ramWritePage(metaAddr);
}

[[noreturn]] OTA_RAMFUNC void ramInstall(const InstallCtx *c)
{
    // Invalid first: a power cut from here until the end leaves the bootloader in OTA DFU (recoverable over BLE).
    ramSetBank0(BANK_INVALID_APP, 0);
    size_t inPos = 0;
    uint32_t out = c->appStart, total = 0;
    bool end = false;
    while (!end) {
        uint8_t *buf = reinterpret_cast<uint8_t *>(pageBuf);
        size_t fill = 0;
        while (fill < OTA_PAGE) {
            ota_unxz_ret r = ota_unxz_run(c->dec, c->in, &inPos, c->inLen, buf, &fill, OTA_PAGE);
            if (r == OTA_UNXZ_END) {
                end = true;
                break;
            }
            if (r != OTA_UNXZ_OK || (fill < OTA_PAGE && inPos >= c->inLen))
                hw::systemReset(); // corrupt stream: stays invalid, bootloader waits in DFU
        }
        if (fill == 0)
            break;
        for (size_t i = fill; i < OTA_PAGE; i++)
            buf[i] = 0xFF;
        ramWritePage(out);
        out += OTA_PAGE;
        total += fill;
    }
    if (total != c->outLen)
        hw::systemReset();
    ramSetBank0(BANK_VALID_APP, total);
    ramMarkInstalled(c->metaAddr);
    hw::systemReset();
}

} // namespace

void requestInstall()
{
    hw::gpregretSet(INSTALL_MAGIC);
}

void installIfRequested()
{
    if (hw::gpregretGet() != INSTALL_MAGIC)
        return;
    hw::gpregretSet(0); // one attempt per request, whatever happens
    OtaStaging st;
    st.load();
    if (st.state() != StagingState::Ready)
        return;
    const ota_common::Manifest &m = st.manifest();
    InstallCtx c{};
    c.dec = ota_unxz_create(m.reserved0 & 0xFF, (m.flags & FLAG_ARMTHUMB) != 0);
    if (!c.dec)
        return;
    c.in = reinterpret_cast<const uint8_t *>(static_cast<uintptr_t>(st.stagingStart()));
    c.inLen = m.payload_length;
    c.appStart = appStart();
    c.outLen = m.output_length;
    c.metaAddr = OTA_META_ADDR;
    hw::irqDisable();
    ramInstall(&c);
}

#if !defined(OTA_HOST_EMU)
namespace hw
{
uint8_t gpregretGet()
{
    return NRF_POWER->GPREGRET & 0xFF;
}

void gpregretSet(uint8_t v)
{
    uint8_t sd = 0;
    sd_softdevice_is_enabled(&sd);
    if (sd) {
        sd_power_gpregret_clr(0, 0xFF);
        sd_power_gpregret_set(0, v);
    } else {
        NRF_POWER->GPREGRET = v;
    }
}

OTA_RAMFUNC void nvmcErase(uint32_t pageAddr)
{
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Een;
    while (!NRF_NVMC->READY) {
    }
    NRF_NVMC->ERASEPAGE = pageAddr;
    while (!NRF_NVMC->READY) {
    }
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}

OTA_RAMFUNC void nvmcWrite(uint32_t addr, const uint32_t *words, size_t count)
{
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Wen;
    volatile uint32_t *dst = reinterpret_cast<volatile uint32_t *>(addr);
    for (size_t i = 0; i < count; i++) {
        dst[i] = words[i];
        while (!NRF_NVMC->READY) {
        }
    }
    NRF_NVMC->CONFIG = NVMC_CONFIG_WEN_Ren;
}

OTA_RAMFUNC void watchdogFeed()
{
    // The WDT keeps running across the soft reset that started us; reload every enabled channel.
    if (NRF_WDT->RUNSTATUS)
        for (int i = 0; i < 8; i++)
            if (NRF_WDT->RREN & (1u << i))
                NRF_WDT->RR[i] = WDT_RR_RR_Reload;
}

void irqDisable()
{
    __disable_irq();
}

OTA_RAMFUNC void systemReset()
{
    __DSB();
    SCB->AIRCR = (0x5FAUL << SCB_AIRCR_VECTKEY_Pos) | SCB_AIRCR_SYSRESETREQ_Msk;
    __DSB();
    for (;;) {
    }
}
} // namespace hw

// Before setup(), the SoftDevice and FreeRTOS: nothing else touches flash yet.
__attribute__((constructor)) static void loraOtaInstallAtBoot()
{
    installIfRequested();
}
#endif

} // namespace lora_ota

#endif
