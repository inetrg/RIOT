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
 * @brief       Implementation of hardware accelerated AES CTR
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
#include "periph/gpio.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

/*
 * Encrypt a single block
 * in and out can overlap
 */
int aes_encrypt_ctr(cipher_context_t *context, uint8_t nonce_counter[16],
                       uint8_t nonce_len, const uint8_t *input, size_t length,
                       uint8_t *output)
{
    (void) nonce_len;

    CRYPTO_TypeDef* dev = crypto_acquire();

    CRYPTO_AES_CTR128(dev, output, input, length, context->context, nonce_counter, NULL);

    crypto_release(dev);
    return length;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt_ctr(cipher_context_t *context, uint8_t nonce_counter[16],
                       uint8_t nonce_len, const uint8_t *input, size_t length,
                       uint8_t *output)
{
    (void) nonce_len;

    CRYPTO_TypeDef* dev = crypto_acquire();

    CRYPTO_AES_CTR128(dev, output, input, length, context->context, nonce_counter, NULL);

    crypto_release(dev);
    return length;
}
