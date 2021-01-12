/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_efm32
 * @{
 *
 * @file
 * @brief       Hardware specific SHA256 context for use with Gecko SDK
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef SHA256_HWCTX_H
#define SHA256_HWCTX_H

#include "em_cmu.h"
#include "em_crypto.h"
#include "em_device.h"
#include "kernel_defines.h"

#if (IS_ACTIVE(MODULE_PERIPH_HASH_SHA256) && IS_ACTIVE(MODULE_GECKO_SDK))

typedef struct {
    /** global state */
    uint32_t state[8];
    /** processed bytes counter */
    uint32_t count[2];
    /** data buffer */
    unsigned char buf[64];
} sha256_context_t;

#endif /* MODULE_PERIPH_HASH_SHA256 */
#endif /* SHA256_HWCTX_H */
