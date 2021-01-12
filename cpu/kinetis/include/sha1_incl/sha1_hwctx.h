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
 * @brief       Hardware specific SHA1 context for use with Kinetis hardware acceleration
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef SHA1_HWCTX_H
#define SHA1_HWCTX_H

#include <stdint.h>
#include "kernel_defines.h"

#define SHA1_STATE_SIZE     (16)
#define SHA1_DIGEST_SIZE    (20)
#define SHA1_BLOCK_SIZE     (64)

#if (IS_ACTIVE(MODULE_PERIPH_HASH_SHA1) && IS_ACTIVE(MODULE_LIB_MMCAU))
typedef struct {
    unsigned int sha1_state[SHA1_BLOCK_SIZE/sizeof(uint32_t)];
    uint32_t buffer[SHA1_BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t byte_count;
    uint32_t buffer_offset;
} sha1_context;
#endif /* MODULE_PERIPH_HASH_SHA1 */

#endif /* SHA1_HWCTX_H */
