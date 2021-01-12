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

#include <stdint.h>
#include <string.h>

#include "hashes/sha1.h"
#include "sha1_hwctx.h"

#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_hash.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

void sha1_init(sha1_context *ctx)
{
    DEBUG("SHA1 init HW accelerated implementation\n");
    int ret = 0;
    ret = CRYS_HASH_Init(&(ctx->cc310_ctx), CRYS_HASH_SHA1_mode);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Init failed: 0x%x\n", ret);
    }
}

void sha1_update(sha1_context *ctx, const void *data, size_t len)
{
    int ret = 0;
    ret = CRYS_HASH_Update(&(ctx->cc310_ctx), (uint8_t*)data, len);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Update failed: 0x%x\n", ret);
    }
}

void sha1_final(sha1_context *ctx, void *digest)
{
    int ret = 0;
    ret = CRYS_HASH_Finish(&(ctx->cc310_ctx), digest);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Finish failed: 0x%x\n", ret);
    }
}

void sha1(void *digest, const void *data, size_t len)
{
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

void sha1_init_hmac(sha1_context *ctx, const void *key, size_t key_length)
{
    (void) ctx;
    (void) key;
    (void) key_length;
}

void sha1_final_hmac(sha1_context *ctx, void *digest)
{
    (void) ctx;
    (void) digest;
}
