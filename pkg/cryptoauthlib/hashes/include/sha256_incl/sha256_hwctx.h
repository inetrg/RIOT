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
 * @brief       Hardware specific SHA256 header
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#ifndef SHA256_HWCTX_H
#define SHA256_HWCTX_H

#include <stdint.h>
#include "cryptoauthlib.h"

typedef struct {
    atca_sha256_ctx_t atca_sha256_ctx;
} sha256_context_t;

typedef struct {
    atca_hmac_sha256_ctx_t atca_hmac_ctx;
} hmac_context_t;

#endif /* SHA256_HWCTX_H */
