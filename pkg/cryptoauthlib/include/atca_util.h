/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg_cryptoauthlib

 * @{
 *
 * @file
 * @brief       Definitions for external Wake, Idle and Sleep Functions
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#ifndef ATCA_UTIL_H
#define ATCA_UTIL_H

void atecc_wake(void);
void atecc_idle(void);
void atecc_sleep(void);

#endif
