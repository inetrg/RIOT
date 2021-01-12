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
 * @brief       Implementation of hardware accelerated SHA1
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdint.h>
#include <string.h>

#ifdef BOARD_PBA_D_01_KW2X
#include "vendor/MKW21D5.h"
#endif /* BOARD_PBA_D_01_KW2X */

#include "hashes/sha1.h"
#include "sha1_hwctx.h"
#include "cau_api.h"
#include "xtimer.h"

#ifdef FREESCALE_MMCAU
#include <stdlib.h>
#include "cau_api.h"
#endif

#define ENABLE_DEBUG    (0)
#include "debug.h"

void sha1_init(sha1_context *ctx)
{
    DEBUG("SHA1 init HW accelerated implementation\n");
    /* Initialize hash variables */
    cau_sha1_initialize_output(ctx->sha1_state);
    ctx->byte_count = 0;
    ctx->buffer_offset = 0;
}

static void sha1_pad(sha1_context *s)
{
    /* Implement SHA-1 padding (fips180-2 §5.1.1) */
    /* Pad with 0x80 followed by 0x00 until the end of the block */
    uint8_t* b = (uint8_t*) s->buffer;
    b[s->buffer_offset] = 0x80;
    s->buffer_offset++;
    while (s->buffer_offset < 56) {
        b[s->buffer_offset] = 0;
        s->buffer_offset++;
    }

    /* Append length in the last 8 bytes. We're only using 32 bit lengths, but SHA-1 supports 64 bit lengths, so zero pad the top bits */
    for (int i = 0; i < 3; i++) {
        b[s->buffer_offset] = 0;
        s->buffer_offset++;
    }

    for (int i = 0; i < 32; i += 8) {
        b[s->buffer_offset] = s->byte_count >> (29 - i);
        s->buffer_offset++;
    }
    b[s->buffer_offset++] = s->byte_count << 3;

    cau_sha1_hash_n((const unsigned char*)b, 1, s->sha1_state);
}

void sha1_update(sha1_context *ctx, const void *data, size_t len)
{
    /* Find out the number of full blocks to hash and pass them to hash function. Hash function will only hash full blocks */
    int blocks = len/SHA1_BLOCK_LENGTH;
    if (blocks > 0) {
        cau_sha1_hash_n((const unsigned char*)data, blocks, ctx->sha1_state);
    }
    /* Calculate number of bytes that didn't fit into the last block */
    int rest = len%SHA1_BLOCK_LENGTH;

    /* If len is not a multiple of 64, save the remaining bytes in buffer for padding and last hash in sha1_final */
    if (rest > 0) {
        uint8_t* input = (uint8_t*) data;
        uint8_t* b = (uint8_t*) ctx->buffer;
        for (int i = 0; i < rest; i++) {
            b[i] = input[len-rest+i];
            ctx->buffer_offset++;
        }
    }
    ctx->byte_count = len;
}

void sha1_final(sha1_context *ctx, void *digest)
{
    /* Pad to complete the last block */
    sha1_pad(ctx);
    /* Swap byte order back */
    for (int i = 0; i < 5; i++) {
        ctx->sha1_state[i] =
            (((ctx->sha1_state[i]) << 24) & 0xff000000)
            | (((ctx->sha1_state[i]) << 8) & 0x00ff0000)
            | (((ctx->sha1_state[i]) >> 8) & 0x0000ff00)
            | (((ctx->sha1_state[i]) >> 24) & 0x000000ff);
    }
    memcpy(digest, &ctx->sha1_state, SHA1_DIGEST_LENGTH);
}

void sha1(void *digest, const void *data, size_t len)
{
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_init_hmac(sha1_context *ctx, const void *key, size_t key_length)
{
    (void) ctx;
    (void) key;
    (void) (key_length);
}

void sha1_final_hmac(sha1_context *ctx, void *digest)
{
    (void) ctx;
    (void) digest;
}
