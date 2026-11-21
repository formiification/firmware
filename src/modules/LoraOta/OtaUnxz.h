// Streaming decoder for LoRa OTA payloads: raw LZMA2 (xz --format=raw --lzma2), optionally
// preceded by the ARM-Thumb BCJ filter (xz --armthumb). Wraps xz-embedded in multi-call
// PREALLOC mode, so RAM use is bounded by the dictionary size (4 KiB in our packages) plus
// ~28 KB of decoder state.
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { OTA_UNXZ_OK = 0, OTA_UNXZ_END = 1, OTA_UNXZ_ERROR = -1, OTA_UNXZ_NOMEM = -2 } ota_unxz_ret;

typedef struct ota_unxz ota_unxz;

// dict_props: the LZMA2 dictionary property byte (0 = 4 KiB, 8 = 64 KiB, ...).
// armthumb: non-zero when the payload was produced with the ARM-Thumb BCJ filter.
ota_unxz *ota_unxz_create(uint8_t dict_props, int armthumb);
// Decode as much as possible from in[*in_pos..in_len) into out[*out_pos..out_len).
ota_unxz_ret ota_unxz_run(ota_unxz *d, const uint8_t *in, size_t *in_pos, size_t in_len, uint8_t *out, size_t *out_pos,
                          size_t out_len);
void ota_unxz_destroy(ota_unxz *d);

#ifdef __cplusplus
}
#endif
