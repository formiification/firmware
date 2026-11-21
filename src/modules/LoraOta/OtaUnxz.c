#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA

#define XZ_DEC_PREALLOC
#define XZ_DEC_ARMTHUMB
#define XZ_EXTERN static OTA_RAMFUNC

// xz-embedded @ 52f2742 (0BSD, xz/COPYING); fork change: functions tagged OTA_RAMFUNC so the installer can
// decode from RAM while the application flash is being rewritten.
#include "OtaUnxz.h"
#include "xz/xz_dec_lzma2.inc"
#include "xz/xz_dec_bcj.inc"

#undef memcpy
#undef memmove
#undef memset
#undef memcmp
#define OTA_RAM_NOLIBC OTA_RAMFUNC __attribute__((optimize("no-tree-loop-distribute-patterns")))

OTA_RAM_NOLIBC void *ota_ram_memcpy(void *d, const void *s, size_t n)
{
    uint8_t *dd = (uint8_t *)d;
    const uint8_t *ss = (const uint8_t *)s;
    while (n--)
        *dd++ = *ss++;
    return d;
}

OTA_RAM_NOLIBC void *ota_ram_memmove(void *d, const void *s, size_t n)
{
    uint8_t *dd = (uint8_t *)d;
    const uint8_t *ss = (const uint8_t *)s;
    if (dd < ss) {
        while (n--)
            *dd++ = *ss++;
    } else {
        dd += n;
        ss += n;
        while (n--)
            *--dd = *--ss;
    }
    return d;
}

OTA_RAM_NOLIBC void *ota_ram_memset(void *d, int c, size_t n)
{
    uint8_t *dd = (uint8_t *)d;
    while (n--)
        *dd++ = (uint8_t)c;
    return d;
}

OTA_RAM_NOLIBC int ota_ram_memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    for (; n; n--, x++, y++)
        if (*x != *y)
            return *x - *y;
    return 0;
}

struct ota_unxz {
    struct xz_dec_lzma2 *lzma2;
    struct xz_dec_bcj *bcj; // NULL when no filter
};

static uint32_t dict_size_from_props(uint8_t props)
{
    // LZMA2 dictionary size encoding (see xz_dec_lzma2_reset)
    return (2u + (props & 1u)) << (props / 2u + 11u);
}

ota_unxz *ota_unxz_create(uint8_t dict_props, int armthumb)
{
    if (dict_props > 39)
        return NULL;
    ota_unxz *d = (ota_unxz *)calloc(1, sizeof(*d));
    if (!d)
        return NULL;
    d->lzma2 = xz_dec_lzma2_create(XZ_PREALLOC, dict_size_from_props(dict_props));
    if (!d->lzma2 || xz_dec_lzma2_reset(d->lzma2, dict_props) != XZ_OK) {
        ota_unxz_destroy(d);
        return NULL;
    }
    if (armthumb) {
        d->bcj = xz_dec_bcj_create(false);
        if (!d->bcj || xz_dec_bcj_reset(d->bcj, BCJ_ARMTHUMB) != XZ_OK) {
            ota_unxz_destroy(d);
            return NULL;
        }
    }
    return d;
}

OTA_RAMFUNC ota_unxz_ret ota_unxz_run(ota_unxz *d, const uint8_t *in, size_t *in_pos, size_t in_len, uint8_t *out, size_t *out_pos,
                          size_t out_len)
{
    struct xz_buf b;
    b.in = in;
    b.in_pos = *in_pos;
    b.in_size = in_len;
    b.out = out;
    b.out_pos = *out_pos;
    b.out_size = out_len;
    enum xz_ret r = d->bcj ? xz_dec_bcj_run(d->bcj, d->lzma2, &b) : xz_dec_lzma2_run(d->lzma2, &b);
    *in_pos = b.in_pos;
    *out_pos = b.out_pos;
    if (r == XZ_OK)
        return OTA_UNXZ_OK;
    if (r == XZ_STREAM_END)
        return OTA_UNXZ_END;
    if (r == XZ_MEM_ERROR)
        return OTA_UNXZ_NOMEM;
    return OTA_UNXZ_ERROR;
}

void ota_unxz_destroy(ota_unxz *d)
{
    if (!d)
        return;
    if (d->bcj)
        kfree(d->bcj);
    if (d->lzma2)
        xz_dec_lzma2_end(d->lzma2);
    free(d);
}

#endif
