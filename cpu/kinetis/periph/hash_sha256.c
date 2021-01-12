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

#include <string.h>
#include <assert.h>
#include <stdlib.h>

#ifdef BOARD_PBA_D_01_KW2X
#include "vendor/MKW21D5.h"
#endif /* BOARD_PBA_D_01_KW2X */

#include "hashes/sha256.h"
#include "sha256_hwctx.h"
#include "mmcau.h"
#include "cau_api.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#ifdef __BIG_ENDIAN__
/* Copy a vector of big-endian uint32_t into a vector of bytes */
#define be32enc_vect memcpy

/* Copy a vector of bytes into a vector of big-endian uint32_t */
#define be32dec_vect memcpy

#else /* !__BIG_ENDIAN__ */

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static void be32enc_vect(void *dst_, const void *src_, size_t len)
{
    if ((uintptr_t)dst_ % sizeof(uint32_t) == 0 &&
        (uintptr_t)src_ % sizeof(uint32_t) == 0) {
        uint32_t *dst = dst_;
        const uint32_t *src = src_;
        for (size_t i = 0; i < len / 4; i++) {
            dst[i] = __builtin_bswap32(src[i]);
        }
    }
    else {
        uint8_t *dst = dst_;
        const uint8_t *src = src_;
        for (size_t i = 0; i < len; i += 4) {
            dst[i] = src[i + 3];
            dst[i + 1] = src[i + 2];
            dst[i + 2] = src[i + 1];
            dst[i + 3] = src[i];
        }
    }
}

/*
 * Decode a big-endian length len vector of (unsigned char) into a length
 * len/4 vector of (uint32_t).  Assumes len is a multiple of 4.
 */
#define be32dec_vect be32enc_vect

#endif /* __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__ */

/* SHA-256 initialization.  Begins a SHA-256 operation. */
void sha256_init(sha256_context_t *ctx)
{
    DEBUG("SHA256 init HW accelerated implementation\n");
    cau_sha256_initialize_output(ctx->sha256_state);
    ctx->count[0] = ctx->count[1] = 0;
}

static unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static void sha_pad(sha256_context_t *ctx)
{
    unsigned char len[8];

    be32enc_vect(len, ctx->count, 8);

    /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
    uint32_t r = (ctx->count[1] >> 3) & 0x3f;
    uint32_t plen = (r < 56) ? (56 - r) : (120 - r);
    sha256_update(ctx, PAD, (size_t) plen);

    /* Add the terminating bit-count */
    sha256_update(ctx, len, 8);

}

/* Add bytes into the hash */
void sha256_update(sha256_context_t *ctx, const void *data, size_t len)
{
    /* Number of bytes left in the buffer from previous updates */
    uint32_t r = (ctx->count[1] >> 3) & 0x3f;

    /* Convert the length into a number of bits */
    uint32_t bitlen1 = ((uint32_t) len) << 3;
    uint32_t bitlen0 = ((uint32_t) len) >> 29;

    /* Update number of bits */
    if ((ctx->count[1] += bitlen1) < bitlen1) {
        ctx->count[0]++;
    }

    ctx->count[0] += bitlen0;

    /* Handle the case where we don't need to perform any transforms */
    if (len < 64 - r) {
        if (len > 0) {
            memcpy(&ctx->buf[r], data, len);
        }
        return;
    }

    /* Finish the current block */
    const unsigned char *src = data;

    memcpy(&ctx->buf[r], src, 64 - r);
    cau_sha256_hash_n(ctx->buf, 1, ctx->sha256_state);
    src += 64 - r;
    len -= 64 - r;

    /* Perform complete blocks */
    while (len >= 64) {
        cau_sha256_hash_n(src, 1, ctx->sha256_state);
        src += 64;
        len -= 64;
    }

    /* Copy left over data into buffer */
    memcpy(ctx->buf, src, len);
}

/*
 * SHA-256 finalization.  Pads the input data, exports the hash value,
 * and clears the context state.
 */
void sha256_final(sha256_context_t *ctx, void *dst)
{
    sha_pad(ctx);

    /* Write the hash */
    be32enc_vect(dst, ctx->sha256_state, SHA256_DIGEST_LENGTH);

    /* Clear the context state */
    memset((void *) ctx, 0, sizeof(*ctx));
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
    unsigned char k[SHA256_INTERNAL_BLOCK_SIZE];

    memset((void *)k, 0x00, SHA256_INTERNAL_BLOCK_SIZE);

    if (key_length > SHA256_INTERNAL_BLOCK_SIZE) {
        sha256(key, key_length, k);
    }
    else {
        memcpy((void *)k, key, key_length);
    }

    /*
     * create the inner and outer keypads
     * rising hamming distance enforcing i_* and o_* are distinct
     * in at least one bit
     */
    unsigned char o_key_pad[SHA256_INTERNAL_BLOCK_SIZE];
    unsigned char i_key_pad[SHA256_INTERNAL_BLOCK_SIZE];

    for (size_t i = 0; i < SHA256_INTERNAL_BLOCK_SIZE; ++i) {
        o_key_pad[i] = 0x5c ^ k[i];
        i_key_pad[i] = 0x36 ^ k[i];
    }

    /*
     * Initiate calculation of the inner hash
     * tmp = hash(i_key_pad CONCAT message)
     */
    sha256_init(&ctx->c_in);
    sha256_update(&ctx->c_in, i_key_pad, SHA256_INTERNAL_BLOCK_SIZE);

    /*
     * Initiate calculation of the outer hash
     * result = hash(o_key_pad CONCAT tmp)
     */
    sha256_init(&ctx->c_out);
    sha256_update(&ctx->c_out, o_key_pad, SHA256_INTERNAL_BLOCK_SIZE);
}

void hmac_sha256_update(hmac_context_t *ctx, const void *data, size_t len)
{
    sha256_update(&ctx->c_in, data, len);
}

void hmac_sha256_final(hmac_context_t *ctx, void *digest)
{
    unsigned char tmp[SHA256_DIGEST_LENGTH];

    static unsigned char m[SHA256_DIGEST_LENGTH];

    if (digest == NULL) {
        digest = m;
    }
    sha256_final(&ctx->c_in, tmp);
    sha256_update(&ctx->c_out, tmp, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx->c_out, digest);

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
 *
 */
static inline void sha256_inplace(unsigned char element[SHA256_DIGEST_LENGTH])
{
    sha256_context_t ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, element, SHA256_DIGEST_LENGTH);
    sha256_final(&ctx, element);
}

void *sha256_chain(const void *seed, size_t seed_length,
                   size_t elements, void *tail_element)
{
    unsigned char tmp_element[SHA256_DIGEST_LENGTH];

    /* assert if no sha256-chain can be created */
    assert(elements >= 2);

    /* 1st iteration */
    sha256(seed, seed_length, tmp_element);

    /* perform consecutive iterations minus the first one */
    for (size_t i = 0; i < (elements - 1); ++i) {
        sha256_inplace(tmp_element);
    }

    /* store the result */
    memcpy(tail_element, tmp_element, SHA256_DIGEST_LENGTH);

    return tail_element;
}

void *sha256_chain_with_waypoints(const void *seed,
                                  size_t seed_length,
                                  size_t elements,
                                  void *tail_element,
                                  sha256_chain_idx_elm_t *waypoints,
                                  size_t *waypoints_length)
{
    /* assert if no sha256-chain can be created */
    assert(elements >= 2);

    /* assert to prevent division by 0 */
    assert(*waypoints_length > 0);

    /* assert if no waypoints can be created */
    assert(*waypoints_length > 1);

    /* if we have enough space we store the whole chain */
    if (*waypoints_length >= elements) {
        /* 1st iteration */
        sha256(seed, seed_length, waypoints[0].element);
        waypoints[0].index = 0;

        /* perform consecutive iterations starting at index 1*/
        for (size_t i = 1; i < elements; ++i) {
            sha256_context_t ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, waypoints[(i - 1)].element, SHA256_DIGEST_LENGTH);
            sha256_final(&ctx, waypoints[i].element);
            waypoints[i].index = i;
        }

        /* store the result */
        memcpy(tail_element, waypoints[(elements - 1)].element, SHA256_DIGEST_LENGTH);
        *waypoints_length = (elements - 1);

        return tail_element;
    }
    else {
        unsigned char tmp_element[SHA256_DIGEST_LENGTH];
        size_t waypoint_streak = (elements / *waypoints_length);

        /* 1st waypoint iteration */
        sha256(seed, seed_length, tmp_element);
        for (size_t i = 1; i < waypoint_streak; ++i) {
            sha256_inplace(tmp_element);
        }
        memcpy(waypoints[0].element, tmp_element, SHA256_DIGEST_LENGTH);
        waypoints[0].index = (waypoint_streak - 1);

        /* index of the current computed element in the chain */
        size_t index = (waypoint_streak - 1);

        /* consecutive waypoint iterations */
        size_t j = 1;
        for (; j < *waypoints_length; ++j) {
            for (size_t i = 0; i < waypoint_streak; ++i) {
                sha256_inplace(tmp_element);
                index++;
            }
            memcpy(waypoints[j].element, tmp_element, SHA256_DIGEST_LENGTH);
            waypoints[j].index = index;
        }

        /* store/pass the last used index in the waypoint array */
        *waypoints_length = (j - 1);

        /* remaining iterations down to elements */
        for (size_t i = index; i < (elements - 1); ++i) {
            sha256_inplace(tmp_element);
        }

        /* store the result */
        memcpy(tail_element, tmp_element, SHA256_DIGEST_LENGTH);

        return tail_element;
    }
}

int sha256_chain_verify_element(void *element,
                                size_t element_index,
                                void *tail_element,
                                size_t chain_length)
{
    unsigned char tmp_element[SHA256_DIGEST_LENGTH];

    int delta_count = (chain_length - element_index);

    /* assert if we have an index mismatch */
    assert(delta_count >= 1);

    memcpy((void *)tmp_element, element, SHA256_DIGEST_LENGTH);

    /* perform all consecutive iterations down to tail_element */
    for (int i = 0; i < (delta_count - 1); ++i) {
        sha256_inplace(tmp_element);
    }

    /* return if the computed element equals the tail_element */
    return (memcmp(tmp_element, tail_element, SHA256_DIGEST_LENGTH) != 0);
}
