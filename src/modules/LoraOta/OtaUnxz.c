#if defined(MESHTASTIC_LORA_OTA) && MESHTASTIC_LORA_OTA

#define XZ_DEC_PREALLOC
#define XZ_DEC_ARMTHUMB
#define XZ_EXTERN static

// xz-embedded @ 52f2742 (0BSD, xz/COPYING), raw LZMA2 + ARM-Thumb BCJ only.
#include "OtaUnxz.h"
#include "xz/xz_dec_lzma2.inc"
#include "xz/xz_dec_bcj.inc"

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

ota_unxz_ret ota_unxz_run(ota_unxz *d, const uint8_t *in, size_t *in_pos, size_t in_len, uint8_t *out, size_t *out_pos,
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
