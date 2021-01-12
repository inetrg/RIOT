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
 * @brief       Implementation of hardware accelerated AES 128
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
#include "aes_hwctx.h"

#include "cryptocell_util.h"
#include "vendor/nrf52840.h"
#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/ssi_aes.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

/**
 * Interface to the aes cipher
 */
static const cipher_interface_t aes_interface = {
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    aes_init,
    aes_encrypt,
    aes_decrypt
};
const cipher_id_t CIPHER_AES_128 = &aes_interface;

int aes_init(cipher_context_t *context, const uint8_t *key, uint8_t keySize)
{
    DEBUG("AES init HW accelerated implementation\n");
    /* This implementation only supports a single key size (defined in AES_KEY_SIZE) */
    if (keySize != AES_KEY_SIZE) {
        return CIPHER_ERR_INVALID_KEY_SIZE;
    }

    /* Make sure that context is large enough. If this is not the case,
       you should build with -DAES */
    if (CIPHER_MAX_CONTEXT_SIZE < AES_KEY_SIZE) {
        return CIPHER_ERR_BAD_CONTEXT_SIZE;
    }

    for (unsigned int i = 0; i < SASI_AES_KEY_MAX_SIZE_IN_BYTES; i++) {
        context->cc310_key[i] = key[(i %keySize)];
    }
    context->cc310_key_size = (size_t)keySize;

    return CIPHER_INIT_SUCCESS;
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
int aes_encrypt(const cipher_context_t *context, const uint8_t *plainBlock,
                uint8_t *cipherBlock)
{
    int ret;
    size_t datain_size =  SASI_AES_BLOCK_SIZE_IN_BYTES;
    size_t dataout_size = SASI_AES_BLOCK_SIZE_IN_BYTES;

    SaSiAesUserContext_t *ctx = (SaSiAesUserContext_t *) &context->cc310_ctx;
    SaSiAesUserKeyData_t key;
    key.keySize = context->cc310_key_size;
    key.pKey = (uint8_t*) context->cc310_key;

    ret = SaSi_AesInit(ctx, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB,SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesInit failed: 0x%x\n", ret);
    }

    ret = SaSi_AesSetKey(ctx, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesSetKey failed: 0x%x\n", ret);
    }

    cryptocell_enable();
    ret = SaSi_AesFinish(ctx, datain_size, (uint8_t*) plainBlock, datain_size, cipherBlock, &dataout_size);
    cryptocell_disable();
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Encryption: SaSi_AesFinish failed: 0x%x\n", ret);
    }

    return 1;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt(const cipher_context_t *context, const uint8_t *cipherBlock,
                uint8_t *plainBlock)
{
    int ret;
    size_t datain_size =  SASI_AES_BLOCK_SIZE_IN_BYTES;
    size_t dataout_size = SASI_AES_BLOCK_SIZE_IN_BYTES;

    SaSiAesUserContext_t *ctx = (SaSiAesUserContext_t *) &context->cc310_ctx;
    SaSiAesUserKeyData_t key;
    key.keySize = context->cc310_key_size;
    key.pKey = (uint8_t*)context->cc310_key;

    ret = SaSi_AesInit(ctx, SASI_AES_DECRYPT, SASI_AES_MODE_ECB,SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Decryption: SaSi_AesInit failed: 0x%x\n", ret);
    }

    ret = SaSi_AesSetKey(ctx, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Decryption: SaSi_AesSetKey failed: 0x%x\n", ret);
    }

    cryptocell_enable();
    ret = SaSi_AesFinish(ctx, datain_size, (uint8_t*) cipherBlock, datain_size, plainBlock, &dataout_size);
    cryptocell_disable();
    if (ret != SA_SILIB_RET_OK) {
        printf("AES Decryption: SaSi_AesFinish failed: 0x%x\n", ret);
    }

    return 1;
}
