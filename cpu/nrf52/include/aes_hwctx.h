#ifndef AES_HWCTX_H
#define AES_HWCTX_H

#include "cryptocell_incl/ssi_aes.h"
#include "kernel_defines.h"

#if (IS_ACTIVE(MODULE_PERIPH_CRYPTO_AES) && IS_ACTIVE(MODULE_LIB_CRYPTOCELL))

typedef struct {
    SaSiAesUserContext_t cc310_ctx;
    uint8_t cc310_key[SASI_AES_KEY_MAX_SIZE_IN_BYTES];
    size_t cc310_key_size;
} cipher_context_t;

#endif /* MODULE_PERIPH_HASH_AES */
#endif /* AES_HWCTX_H */