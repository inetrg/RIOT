/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_kinetis
 * @{
 *
 * @file
 * @brief       Hardware specific SHA256 context for use with Kinetis hardware acceleration
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef SHA256_HWCTX_H
#define SHA256_HWCTX_H

#include "kernel_defines.h"

#define SHA256_STATE_SIZE   (8)
#define SHA256_DIGEST_SIZE  (32)
#define SHA256_BLOCK_SIZE   (64)

#if (IS_ACTIVE(MODULE_PERIPH_HASH_SHA256) && IS_ACTIVE(MODULE_LIB_MMCAU))
typedef struct {
    unsigned int sha256_state[SHA256_STATE_SIZE];
    uint32_t count[2];
    unsigned char buf[64];
} sha256_context_t;
#endif /* MODULE_PERIPH_HASH_SHA256 */

#endif /* SHA256_HWCTX_H */