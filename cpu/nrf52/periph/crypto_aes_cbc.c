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
 * @brief       Implementation of hardware accelerated AES CBC
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/aes.h"
#include "crypto/ciphers.h"
#include "vendor/nrf52840.h"
#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/ssi_aes.h"
#include "cryptocell_util.h"

#include "periph/gpio.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if TEST_AES_KEY
    extern gpio_t gpio_aes_key;
#endif

/* CC310 max AES input block is 64 KB */
#define CC310_MAX_AES_INPUT_BLOCK       (0xFFF0)

/*
 * Encrypt a single block
 * in and out can overlap
 */
int aes_encrypt_cbc(cipher_context_t *context, uint8_t iv[16],
                       const uint8_t *input, size_t length, uint8_t *output)
{
    int ret;
    size_t offset = 0;
    size_t size;

    if (length % AES_BLOCK_SIZE != 0) {
        return CIPHER_ERR_INVALID_LENGTH;
    }
    SaSiAesUserContext_t *ctx = (SaSiAesUserContext_t *) &context->cc310_ctx;
    SaSiAesUserKeyData_t key;
    key.keySize = context->cc310_key_size;
    key.pKey = (uint8_t*) context->cc310_key;

    ret = SaSi_AesInit(ctx, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesInit failed: 0x%x\n", ret);
        return -1;
    }
#if TEST_AES_KEY
    gpio_set(gpio_aes_key);
#endif
    ret = SaSi_AesSetKey(ctx, SASI_AES_USER_KEY, &key, sizeof(key));
#if TEST_AES_KEY
    gpio_clear(gpio_aes_key);
#endif

    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesSetKey failed: 0x%x\n", ret);
        return -1;
    }
    ret = SaSi_AesSetIv(ctx, iv);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesSetIV failed: 0x%x\n", ret);
        return -1;
    }

    do {
        if (length > CC310_MAX_AES_INPUT_BLOCK) {
            size = CC310_MAX_AES_INPUT_BLOCK;
            length -= CC310_MAX_AES_INPUT_BLOCK;
        }
        else {
            size = length;
            length = 0;
        }

        cryptocell_enable();
        ret = SaSi_AesBlock(ctx, (uint8_t*)(input + offset), size, output + offset);

        cryptocell_disable();

        offset += size;
    } while ((length > 0) && (ret == SA_SILIB_RET_OK));

    cryptocell_enable();
    ret = SaSi_AesFinish(ctx, length, (uint8_t*)(input + offset), length, output, &length);
    cryptocell_disable();

    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesFinish failed: 0x%x\n", ret);
        return -1;
    }
    return offset;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt_cbc(cipher_context_t *context, uint8_t iv[16],
                       const uint8_t *input, size_t length, uint8_t *output)
{
    int ret;
    size_t offset = 0;
    size_t size;

    if (length % AES_BLOCK_SIZE != 0) {
        return CIPHER_ERR_INVALID_LENGTH;
    }
    SaSiAesUserContext_t *ctx = (SaSiAesUserContext_t *) &context->cc310_ctx;
    SaSiAesUserKeyData_t key;
    key.keySize = context->cc310_key_size;
    key.pKey = (uint8_t*) context->cc310_key;

    ret = SaSi_AesInit(ctx, SASI_AES_DECRYPT, SASI_AES_MODE_CBC,SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesInit failed: 0x%x\n", ret);
        return -1;
    }

#if TEST_AES_KEY
    gpio_set(gpio_aes_key);
#endif
    ret = SaSi_AesSetKey(ctx, SASI_AES_USER_KEY, &key, sizeof(key));
#if TEST_AES_KEY
    gpio_clear(gpio_aes_key);
#endif
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesSetKey failed: 0x%x\n", ret);
        return -1;
    }
    ret = SaSi_AesSetIv(ctx, iv);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesSetIV failed: 0x%x\n", ret);
        return -1;
    }

    do {
        if (length > CC310_MAX_AES_INPUT_BLOCK) {
            size = CC310_MAX_AES_INPUT_BLOCK;
            length -= CC310_MAX_AES_INPUT_BLOCK;
        }
        else {
            size = length;
            length = 0;
        }

        cryptocell_enable();
        ret = SaSi_AesBlock(ctx, (uint8_t*)(input + offset), size, output + offset);
        cryptocell_disable();

        offset += size;
    } while ((length > 0) && (ret == SA_SILIB_RET_OK));

    cryptocell_enable();
    ret = SaSi_AesFinish(ctx, length, (uint8_t*)(input + offset), length, output, &length);
    cryptocell_disable();

    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesFinish failed: 0x%x\n", ret);
        return -1;
    }
    return offset;
}
