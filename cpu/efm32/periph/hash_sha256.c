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
 * @brief       Implementation of hardware accelerated SHA256 operation
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <string.h>
#include <assert.h>

#include "em_crypto.h"
#include "em_core.h"
#include "crypto_util.h"
#include "hashes/sha256.h"
#include "sha256_hwctx.h"

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
    /* Assert if len is not a multiple of 4 */
    assert(!(len & 3));

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

static unsigned char PAD[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* Add padding and terminating bit-count. */
static void sha256_pad(sha256_context_t *ctx)
{
    /*
     * Convert length to a vector of bytes -- we do this now rather
     * than later because the length will change after we pad.
     */
    unsigned char len[8];

    be32enc_vect(len, ctx->count, 8);

    /* Add 1--64 bytes so that the resulting length is 56 mod 64 */
    uint32_t r = (ctx->count[1] >> 3) & 0x3f;
    uint32_t plen = (r < 56) ? (56 - r) : (120 - r);
    sha256_update(ctx, PAD, (size_t) plen);

    /* Add the terminating bit-count */
    sha256_update(ctx, len, 8);
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
     /* Zero bits processed so far */
    ctx->count[0] = ctx->count[1] = 0;

    /* Magic initialization constants */
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

static void sha256_update_state(sha256_context_t* ctx, const unsigned char* data, size_t blocks)
{
    CORE_DECLARE_IRQ_STATE;
    CRYPTO_TypeDef* dev = crypto_acquire();

    /* Write mode to control register of crypto device */
    dev->CTRL = CRYPTO_CTRL_SHA_SHA2;
    /*  Clear Wide Arithmetic Configuration. WAC determines width of operation when performing arithmetic/shift instructions. */
    dev->WAC = 0;
    /* Clear Interrupt Enable Register */
    dev->IEN = 0;

    /* Set result width of MADD32 operation. Write result to WAC*/
    CRYPTO_ResultWidthSet(dev, cryptoResult256Bits);

    /* Clear sequence control registers */
    dev->SEQCTRL  = 0;
    dev->SEQCTRLB = 0;

    CORE_ENTER_CRITICAL();
    CRYPTO_DDataWrite(&dev->DDATA1, ctx->state);
    CORE_EXIT_CRITICAL();

    CRYPTO_EXECUTE_3(   dev,
                        CRYPTO_CMD_INSTR_DDATA1TODDATA0,
                        CRYPTO_CMD_INSTR_DDATA1TODDATA2,
                        CRYPTO_CMD_INSTR_SELDDATA0DDATA1 );

    /* Load data blocks */
    for (size_t i = 0; i < blocks; i++) {
        if ((uint32_t)(&data[i*SHA256_INTERNAL_BLOCK_SIZE]) & 0x3) {
            uint32_t temp[SHA256_INTERNAL_BLOCK_SIZE/sizeof(uint32_t)];
            memcpy(temp, &data[i*SHA256_INTERNAL_BLOCK_SIZE], SHA256_INTERNAL_BLOCK_SIZE);
            CORE_ENTER_CRITICAL();
            CRYPTO_QDataWrite(&dev->QDATA1BIG, temp);
            CORE_EXIT_CRITICAL();
        }
        else {
            CORE_ENTER_CRITICAL();
            CRYPTO_QDataWrite(&dev->QDATA1BIG, (uint32_t*)&data[i*SHA256_INTERNAL_BLOCK_SIZE]);
            CORE_EXIT_CRITICAL();
        }

        CRYPTO_EXECUTE_3(   dev,
                            CRYPTO_CMD_INSTR_SHA,
                            CRYPTO_CMD_INSTR_MADD32,
                            CRYPTO_CMD_INSTR_DDATA0TODDATA1 );
    }

    CORE_ENTER_CRITICAL();
    CRYPTO_DDataRead(&dev->DDATA0, ctx->state);
    CORE_EXIT_CRITICAL();

    crypto_release(dev);
}

static void sha256_transform_block(sha256_context_t* ctx, const unsigned char block[64])
{
    sha256_update_state(ctx, block, 1);
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
    sha256_transform_block(ctx, ctx->buf);
    src += 64 - r;
    len -= 64 - r;

    /* Perform complete blocks */
    while (len >= 64) {
        sha256_transform_block(ctx, src);
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
    /* Add padding */
    sha256_pad(ctx);

    /* Write the hash */
    be32enc_vect(dst, ctx->state, SHA256_DIGEST_LENGTH);

    /* Clear the context state */
    memset((void *) ctx, 0, sizeof(*ctx));
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
//  * @brief helper to compute sha256 inplace for the given buffer
//  *
//  * @param[in, out] element the buffer to compute a sha256 and store it back to it
//  *
//  */
// static inline void sha256_inplace(unsigned char element[SHA256_DIGEST_LENGTH])
// {
//     (void) element;
// }

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
