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
 * @brief       Hardware specific SHA1 context for use with Gecko SDK
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef SHA1_HWCTX_H
#define SHA1_HWCTX_H

#include "em_cmu.h"
#include "em_crypto.h"
#include "em_device.h"
#include "kernel_defines.h"

#if (IS_ACTIVE(MODULE_PERIPH_HASH_SHA1) && IS_ACTIVE(MODULE_GECKO_SDK))

typedef struct {
    CRYPTO_SHA1_Digest_TypeDef digest;
} sha1_context;

#endif /* MODULE_PERIPH_HASH_SHA1 */
#endif /* SHA1_HWCTX_H */
