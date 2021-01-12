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
#include "crypto_util.h"

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
    uint8_t i;

    /* This implementation only supports a single key size (defined in AES_KEY_SIZE) */
    if (keySize != AES_KEY_SIZE) {
        return CIPHER_ERR_INVALID_KEY_SIZE;
    }

    /* Make sure that context is large enough. If this is not the case,
       you should build with -DAES */
    if (CIPHER_MAX_CONTEXT_SIZE < AES_KEY_SIZE) {
        return CIPHER_ERR_BAD_CONTEXT_SIZE;
    }

    /* key must be at least CIPHERS_MAX_KEY_SIZE Bytes long */
    if (keySize < CIPHERS_MAX_KEY_SIZE) {
        /* fill up by concatenating key to as long as needed */
        for (i = 0; i < CIPHERS_MAX_KEY_SIZE; i++) {
            context->context[i] = key[(i % keySize)];
        }
    }
    else {
        for (i = 0; i < CIPHERS_MAX_KEY_SIZE; i++) {
            context->context[i] = key[i];
        }
    }
    return CIPHER_INIT_SUCCESS;
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
int aes_encrypt(const cipher_context_t *context, const uint8_t *plainBlock,
                uint8_t *cipherBlock)
{
    CRYPTO_TypeDef* dev = crypto_acquire();

    CRYPTO_AES_ECB128(dev, cipherBlock, plainBlock, AES_BLOCK_SIZE, context->context, true);

    crypto_release(dev);
    return 1;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt(const cipher_context_t *context, const uint8_t *cipherBlock,
                uint8_t *plainBlock)
{
    uint8_t decrypt_key[AES_KEY_SIZE];

    CRYPTO_TypeDef* dev = crypto_acquire();

    CRYPTO_AES_DecryptKey128(dev, decrypt_key, context->context);
    CRYPTO_AES_ECB128(dev, plainBlock, cipherBlock, AES_BLOCK_SIZE, decrypt_key, false);

    crypto_release(dev);
    return 1;
}
