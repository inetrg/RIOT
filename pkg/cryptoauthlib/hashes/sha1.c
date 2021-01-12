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
 * @brief       Implementation of hardware accelerated SHA1
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdint.h>
#include <string.h>

#include "hashes/sha1.h"
#include "sha1_hwctx.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

void sha1_init(sha1_context *ctx)
{
    (void) ctx;
    DEBUG("SHA-1 init Cryptoauth Lib implementation\n");
}

void sha1_update(sha1_context *ctx, const void *data, size_t len)
{
    (void) ctx;
    (void) data;
    (void) len;
}

void sha1_final(sha1_context *ctx, void *digest)
{
    (void) ctx;
    (void) digest;
}

void sha1(void *digest, const void *data, size_t len)
{
    (void) digest;
    (void) data;
    (void) len;
}

void sha1_init_hmac(sha1_context *ctx, const void *key, size_t key_length)
{
    (void) ctx;
    (void) key;
    (void) key_length;
}

void sha1_final_hmac(sha1_context *ctx, void *digest)
{
    (void) ctx;
    (void) digest;
}
