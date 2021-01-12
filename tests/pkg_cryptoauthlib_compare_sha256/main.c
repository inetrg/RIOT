/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       This test was written to compare the runtime of the RIOT software
 *              implementation and the CryptoAuth hardware implementation of SHA-256.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 * @author      Peter Kietzmann <peter.kietzmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "kernel_defines.h"

#include "hashes/sha256.h"
#include "atca.h"
#include "atca_util.h"
#include "atca_params.h"

#include "shell.h"
#include "xtimer.h"
#include "periph/gpio.h"
#include "periph/i2c.h"

#define SHA256_HASH_SIZE (32)

#ifndef NUM_ITER
#define NUM_ITER 10
#endif

uint32_t start, stop;

uint8_t teststring[] =  "This is a teststring fore sha256";
uint8_t teststring2[] = "einealtedamegehthonigessenxxxxxx";
uint16_t test_string_size = (sizeof(teststring) - 1);   /* -1 to ignore \0 */

uint8_t expected[] =
{
0x65, 0x0C, 0x3A, 0xC7, 0xF9, 0x33, 0x17, 0xD3,
0x96, 0x31, 0xD3, 0xF5, 0xC5, 0x5B, 0x0A, 0x1E,
0x96, 0x68, 0x04, 0xE2, 0x73, 0xC3, 0x8F, 0x93,
0x9C, 0xB1, 0x45, 0x4D, 0xC2, 0x69, 0x7D, 0x20
};

uint8_t result[SHA256_HASH_SIZE];                       /* +3 to fit 1 byte length and 2 bytes checksum */

gpio_t active_gpio = GPIO_PIN(1, 7);
gpio_t gpio_aes_key = GPIO_PIN(1, 8);
gpio_t gpio_sync_pin = GPIO_PIN(1, 6);

static inline void _init_trigger(void)
{
#if TEST_ENERGY
    gpio_init(active_gpio, GPIO_OUT);
    gpio_init(gpio_aes_key, GPIO_OUT);
    gpio_init(gpio_sync_pin, GPIO_IN);

    gpio_set(active_gpio);
    gpio_clear(gpio_aes_key);
#else
    gpio_init(active_gpio, GPIO_OUT);
    gpio_clear(active_gpio);
#endif
}

static inline void _start_trigger(void)
{
#if TEST_ENERGY
    while(gpio_read(gpio_sync_pin)) {};
    while(!gpio_read(gpio_sync_pin)) {};
    // this is crap and it should be fixed! for the fast i2x, manual powering, no save
    // context mode, the device was not responsible when doing the synchronization
    // patter for energy measurements. enabling the device manually helped :/

    // Fix (kind of): Turns out the problem is the device's watchdog timer.
    // After waking up, the WD timer starts and runs for 1.3 s. After that time interval
    // the device automatically returns back to sleep mode. This is not enough time for the
    // measuring instrument.
    // The timer interval can be set to 10 s, but this needs to be done by setting a bit in the
    // configuration zone before locking the device.
#if defined(ATCA_MANUAL_ONOFF) && !defined(NO_I2C_RECONF)
    atecc_wake();
#endif
    gpio_clear(active_gpio);
#else
    gpio_set(active_gpio);
#endif
}

static inline void _stop_trigger(void)
{
#if TEST_ENERGY
    gpio_set(gpio_aes_key);

    gpio_set(active_gpio);
    gpio_clear(gpio_aes_key);
#else
    gpio_clear(active_gpio);
#endif
}

atca_sha256_ctx_t ctx;

#if ATCA_SAVE_CTX
static void ata_with_ctx_save(void)
{

    atca_sha256_ctx_t ctx;
    uint8_t res[SHA256_HASH_SIZE];
    uint8_t context[SHA_CONTEXT_MAX_SIZE];
    memset(context, 0, SHA_CONTEXT_MAX_SIZE);
    uint16_t context_size=sizeof(context);


    start = xtimer_now_usec();
#ifdef ATCA_MANUAL_ONOFF
    atecc_wake();
#endif


    for (int i = 0; i < NUM_ITER; i++) {
        // printf("LOOP #%i\n", i);
        _start_trigger();
        if (atcab_hw_sha2_256_init(&ctx) != ATCA_SUCCESS) {
            puts("atcab_hw_sha2_256_initERROR");
        }
        if (atcab_sha_read_context(context, &context_size) != ATCA_SUCCESS) {
            puts("1atcab_sha_read_contextERROR");
        }

        if (atcab_sha_write_context(context, context_size) != ATCA_SUCCESS) {
            puts("atcab_sha_write_contextERROR");
        }
        if (atcab_hw_sha2_256_update(&ctx, teststring, sizeof(teststring)-1) != ATCA_SUCCESS) {
            puts("atcab_hw_sha2_256_updateERROR");
        }
        if (atcab_sha_read_context(context, &context_size) != ATCA_SUCCESS) {
            puts("2atcab_sha_read_contextERROR");
        }

        if (atcab_sha_write_context(context, context_size) != ATCA_SUCCESS) {
            puts("atcab_sha_write_contextERROR");
        }
        if (atcab_hw_sha2_256_finish(&ctx, res) != ATCA_SUCCESS) {
            puts("atcab_hw_sha2_256_finishERROR");
        }
        _stop_trigger();
    //     if (atcab_sha_read_context(context, &context_size) != ATCA_SUCCESS) {
    //     puts("3atcab_sha_read_contextERROR");
    // }
    }

#ifdef ATCA_MANUAL_ONOFF
    atecc_sleep();
#endif
    stop = xtimer_now_usec();
    printf("ata_with_ctx_save: %i Bytes int %"PRIu32 " us\n", (NUM_ITER*SHA256_HASH_SIZE), (stop-start));

    // if (!memcmp(expected, res, SHA256_HASH_SIZE) == 0) {
    //     puts("ata_with_ctx_save ERROR");
    // }
    // else {
    //     puts("ata_without_ctx_save alrido");
    // }
}
#endif

#ifndef ATCA_SAVE_CTX
static void ata_without_ctx_save(void)
{
    atca_sha256_ctx_t ctx;
    uint8_t res[SHA256_HASH_SIZE];

    start = xtimer_now_usec();
#ifdef ATCA_MANUAL_ONOFF
    atecc_wake();
#endif

    ATCA_STATUS status;
    // _start_trigger();
    for (int i = 0; i < NUM_ITER; i++) {
        _start_trigger();// should actually be here :/
        status=atcab_hw_sha2_256_init(&ctx);
        if (status != ATCA_SUCCESS) {
            printf("atcab_hw_sha2_256_init ERROR: %x, %i\n", status,i);
        }
        status=atcab_hw_sha2_256_update(&ctx, teststring, sizeof(teststring)-1);
        if (status != ATCA_SUCCESS) {
            printf("atcab_hw_sha2_256_update ERROR: %x, %i\n", status,i);
        }
        status=atcab_hw_sha2_256_finish(&ctx, res);
        if (status != ATCA_SUCCESS) {
            printf("atcab_hw_sha2_256_finish ERROR: %x, %i\n", status,i);
        }
        _stop_trigger();// should actually be here :/
    }
    // _stop_trigger();

#ifdef ATCA_MANUAL_ONOFF
    atecc_sleep();
#endif
    stop = xtimer_now_usec();

    printf("ata_without_ctx_save: %i Bytes int %"PRIu32 " us\n", (NUM_ITER*SHA256_HASH_SIZE), (stop-start));
}
#endif

int main(void)
{

    memset(result, 0, SHA256_HASH_SIZE);                    /* alles in result auf 0 setzen */

    _init_trigger();

#ifdef NO_I2C_RECONF
    puts("SLOW I2C");
#else
    puts("FAST I2C");
#endif

#ifdef MODULE_PERIPH_I2C_RECONFIGURE
    puts("GPIO WAKEUP");
#else
    puts("I2C WAKEUP");
#endif

    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *)&atca_params[I2C_DEV(0)];
    if (i2c_config[cfg->atcai2c.bus].speed == I2C_SPEED_NORMAL) {
        puts("I2C_SPEED_NORMAL");
    }
    if (i2c_config[cfg->atcai2c.bus].speed == I2C_SPEED_FAST) {
        puts("I2C_SPEED_FAST");
    }

#ifdef ATCA_MANUAL_ONOFF
    // sleep initially
    atecc_sleep();
    puts("ATCA_MANUAL_ON");
#else
    puts("ATCA_MANUAL_OFF");
#endif

    // if (test_atca_sha(teststring, test_string_size, expected, result) == 0) {
    //     printf("ATCA SHA256: Success\n");
    // }
    // else {
    //     printf("ATCA SHA256: Failure.\n");
    // }
#if ATCA_SAVE_CTX
    puts("SAVE CTX");
    ata_with_ctx_save();
#else
    puts("NO SAVE CTX");
    ata_without_ctx_save();
#endif

    return 0;
}
