/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_hashes

 * @{
 *
 * @file
 * @brief       Implementation of hardware accelerated SHA256
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdint.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "hashes/sha256.h"
#include "sha256_hwctx.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

void sha256_init(sha256_context_t *ctx)
{
    DEBUG("Cryptoauth SHA256\n");
    atcab_hw_sha2_256_init(&ctx->atca_sha256_ctx);
}

void sha256_update(sha256_context_t *ctx, const void *data, size_t len)
{
    atcab_hw_sha2_256_update(&ctx->atca_sha256_ctx, data, len);
}

void sha256_final(sha256_context_t *ctx, void *dst)
{
    atcab_hw_sha2_256_finish(&ctx->atca_sha256_ctx, dst);
}

void *sha256(const void *data, size_t len, void *digest)
{
    sha256_context_t ctx;
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
    return digest;
}

void hmac_sha256_init(hmac_context_t *ctx, const void *key, size_t key_length)
{
    if (key_length > 32) {
        DEBUG("ERROR: ATCA HMAC key can't be larger than 32 Bytes\n");
    }

    if (atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, key_length) != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA Loading key into TempKey register failed\n");
    }

    if (atcab_sha_hmac_init(&ctx->atca_hmac_ctx, ATCA_TEMPKEY_KEYID) != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA HMAC init failed");
    }

}

void hmac_sha256_update(hmac_context_t *ctx, const void *data, size_t len)
{
    if (atcab_sha_hmac_update(&ctx->atca_hmac_ctx, data, len) != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA HMAC Update failed\n");
    }
}

void hmac_sha256_final(hmac_context_t *ctx, void *digest)
{
    if (atcab_sha_hmac_finish(&ctx->atca_hmac_ctx, digest, SHA_MODE_TARGET_OUT_ONLY) != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA HMAC Finish failed\n");
    }
}

const void *hmac_sha256(const void *key, size_t key_length,
                        const void *data, size_t len, void *digest)
{
    hmac_context_t ctx;

    hmac_sha256_init(&ctx, key, key_length);
    hmac_sha256_update(&ctx,data, len);
    hmac_sha256_final(&ctx, digest);

    return digest;
}

/**
 * @brief helper to compute sha256 inplace for the given buffer
 *
 * @param[in, out] element the buffer to compute a sha256 and store it back to it
 */

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
    return 0;
}
