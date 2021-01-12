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
 * @brief       Specific API for AES CTR
 *
 * @author      Peter Kietzmann <peter.kietzmann@haw-hamburg.de>
 */

#include "crypto/ciphers.h"
#include "crypto/modes/ctr.h"

int aes_encrypt_ctr(cipher_context_t *context, uint8_t nonce_counter[16],
                       uint8_t nonce_len, const uint8_t *input, size_t length,
                       uint8_t *output)
{
     return cipher_encrypt_ctr(context, CIPHER_AES_128, nonce_counter,
                       nonce_len, input, length,
                       output);
}


int aes_decrypt_ctr(cipher_context_t *context, uint8_t nonce_counter[16],
                       uint8_t nonce_len, const uint8_t *input, size_t length,
                       uint8_t *output)
{
     return cipher_decrypt_ctr(context, CIPHER_AES_128, nonce_counter,
                       nonce_len, input, length,
                       output);
}
