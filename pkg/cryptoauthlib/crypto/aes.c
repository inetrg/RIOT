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

#include <stdint.h>
#include <stdlib.h>
#include "cryptoauthlib.h"
#include "crypto/aes.h"
#include "crypto/ciphers.h"
#include "cryptoauthlib_crypto_hwctx.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"
// TODO: define, this is copied from NRF52
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
            context->key[i] = key[(i % keySize)];
        }
    }
    else {
        for (i = 0; i < CIPHERS_MAX_KEY_SIZE; i++) {
            context->key[i] = key[i];
        }
    }

    int status;
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
    if(status != ATCA_SUCCESS) {
        printf("init status %i\n", status);
        return -1;
    }

    return CIPHER_INIT_SUCCESS;
}

int aes_encrypt(const cipher_context_t *context, const uint8_t *plain_block,
                uint8_t *cipher_block)
{
    (void)context;
    int status;

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 0, plain_block, cipher_block);
    if(status != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA AES Encrypt failed");
        return CIPHER_ERR_ENC_FAILED;
    }
    return 1;
}

int aes_decrypt(const cipher_context_t *context, const uint8_t *cipher_block,
                uint8_t *plain_block)
{
    (void)context;
    int status;
    atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, (uint8_t*)&(context->key), 32);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 0, cipher_block, plain_block);
    if(status != ATCA_SUCCESS) {
        DEBUG("ERROR: ATCA AES Decrypt failed");
        return CIPHER_ERR_ENC_FAILED;
    }
    return 1;
}
