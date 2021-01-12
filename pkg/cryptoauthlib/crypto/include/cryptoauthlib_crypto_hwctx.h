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
 * @brief       Hardware specific AES context
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#ifndef CRYPTOAUTHLIB_CRYPTO_HWCTX_H
#define CRYPTOAUTHLIB_CRYPTO_HWCTX_H

#include <stdint.h>
#include "cryptoauthlib.h"
#include "kernel_defines.h"

typedef struct {
#if defined(MODULE_CRYPTOAUTHLIB_CRYPTO_AES_CBC)
    atca_aes_cbc_ctx_t cbc_context;
#endif
#if defined(MODULE_CRYPTOAUTHLIB_CRYPTO_AES_CTR)
    atca_aes_ctr_ctx_t ctr_context;
#endif
    uint8_t key[16];
} cipher_context_t;

#endif /* CRYPTOAUTHLIB_CRYPTO_HWCTX_H */
