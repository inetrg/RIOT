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
 * @brief       Specific API for AES CBC
 *
 * @author      Peter Kietzmann <peter.kietzmann@haw-hamburg.de>
 */

#include "crypto/ciphers.h"
#include "crypto/modes/cbc.h"

int aes_encrypt_cbc(cipher_context_t *context, uint8_t iv[16],
                       const uint8_t *input, size_t length, uint8_t *output)
{
     return cipher_encrypt_cbc(context, CIPHER_AES_128, iv,
                              input, length, output);
}


int aes_decrypt_cbc(cipher_context_t *context, uint8_t iv[16],
                       const uint8_t *input, size_t length, uint8_t *output)
{
     return cipher_decrypt_cbc(context, CIPHER_AES_128, iv,
                              input, length, output);
}
