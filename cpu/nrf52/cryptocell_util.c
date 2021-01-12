/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_nrf52

 * @{
 *
 * @file
 * @brief       Some utility functions to use the cryptocell module
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdio.h>
#include "vendor/nrf52840.h"
#include "cryptocell_incl/sns_silib.h"

void cryptocell_enable(void)
{
    NRF_CRYPTOCELL->ENABLE = 1;
    NVIC_EnableIRQ(CRYPTOCELL_IRQn);
}

void cryptocell_disable(void)
{
    NRF_CRYPTOCELL->ENABLE = 0;
    NVIC_DisableIRQ(CRYPTOCELL_IRQn);
}
