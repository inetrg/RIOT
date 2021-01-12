/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_crypto

 * @{
 *
 * @file
 * @brief       Implementation of hardware accelerated SHA1
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <string.h>
#include <assert.h>

#include "hashes/sha256.h"
#include "sha256_hwctx.h"
#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hmac.h"
#include "cryptocell_incl/crys_error.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define CC310_MAX_HASH_INPUT_BLOCK       (0xFFF0)

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void sha256_init(sha256_context_t *ctx)
{
    DEBUG("SHA256 init HW accelerated implementation\n");
    int ret = 0;
    ret = CRYS_HASH_Init(&ctx->cc310_ctx, CRYS_HASH_SHA256_mode);
    if (ret != CRYS_OK) {
        printf("SHA256: CRYS_HASH_Init failed: 0x%x\n", ret);
    }
}

/* Add bytes into the hash */
void sha256_update(sha256_context_t *ctx, const void *data, size_t len)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;

    do {
        if (len > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            len -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = len;
            len = 0;
        }

        cryptocell_enable();
        ret = CRYS_HASH_Update(&ctx->cc310_ctx, (uint8_t*)(data + offset), size);
        cryptocell_disable();

        offset += size;
    } while ((len > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        printf("SHA256: CRYS_HASH_Update failed: 0x%x\n", ret);
    }
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void sha256_final(sha256_context_t *ctx, void *dst)
{
    int ret = 0;
    cryptocell_enable();
    ret = CRYS_HASH_Finish(&(ctx->cc310_ctx), dst);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("SHA256: CRYS_HASH_Finish failed: 0x%x\n", ret);
    }
}

void *sha256(const void *data, size_t len, void *digest)
{
    sha256_context_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
    return digest;
}

void hmac_sha256_init(hmac_context_t *ctx, const void *key, size_t key_length)
{
    int ret = 0;
    cryptocell_enable();
    CRYS_HMAC_Init(&ctx->cc310_hmac_ctx, CRYS_HASH_SHA256_mode, (uint8_t*)key, (uint16_t)key_length);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("HMAC: CRYS_HMAC_Init failed: 0x%x\n", ret);
    }
}

void hmac_sha256_update(hmac_context_t *ctx, const void *data, size_t len)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;

    do {
        if (len > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            len -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = len;
            len = 0;
        }

        cryptocell_enable();
        ret = CRYS_HMAC_Update(&ctx->cc310_hmac_ctx, (uint8_t*)(data + offset), size);
        cryptocell_disable();

        offset += size;
    } while ((len > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        printf("HMAC: CRYS_HMAC_Update failed: 0x%x\n", ret);
    }
}

void hmac_sha256_final(hmac_context_t *ctx, void *digest)
{
    int ret = 0;
    cryptocell_enable();
    ret = CRYS_HMAC_Finish(&ctx->cc310_hmac_ctx, (uint32_t*)digest);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("HMAC: CRYS_HMAC_Finish failed: 0x%x\n", ret);
    }
}

const void *hmac_sha256(const void *key, size_t key_length,
                        const void *data, size_t len, void *digest)
{
    int ret = 0;
    cryptocell_enable();
    ret = CRYS_HMAC(CRYS_HASH_SHA256_mode, (uint8_t*)key, (uint16_t)key_length, (uint8_t*) data, len, (uint32_t*)digest);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        printf("HMAC: CRYS_HMAC failed: 0x%x\n", ret);
    }
    return digest;
}

void *sha256_chain(const void *seed, size_t seed_length,
                   size_t elements, void *tail_element)
{
    (void) seed;
    (void) seed_length;
    (void) elements;
    (void) tail_element;
    return NULL;
}

void *sha256_chain_with_waypoints(const void *seed,
                                  size_t seed_length,
                                  size_t elements,
                                  void *tail_element,
                                  sha256_chain_idx_elm_t *waypoints,
                                  size_t *waypoints_length)
{
    (void) seed;
    (void) seed_length;
    (void) elements;
    (void) tail_element;
    (void) waypoints;
    (void) waypoints_length;
    return NULL;
}

int sha256_chain_verify_element(void *element,
                                size_t element_index,
                                void *tail_element,
                                size_t chain_length)
{
    (void) element;
    (void) element_index;
    (void) tail_element;
    (void) chain_length;
    return 1;
}
