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
 * @brief       Implementation of some management functions for the efm32 Crypto module
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 * @author      Leandro Lanzieri <leandro.lanzieri@haw-hamburg.de>
 *
 * @}
 */

#include <stdbool.h>
#include <stdio.h>
#include "crypto_util.h"
#include "mutex.h"
#include "xtimer.h"
#include "em_ldma.h"

#include "periph/gpio.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

#if CPU_MODEL_EFM32PG12B500F1024GL125
static bool crypto_lock_initialized = false;
static crypto_device_t crypto_devs[CRYPTO_COUNT] =
{
    #if defined(CRYPTO0)
        {
            CRYPTO0,
            cmuClock_CRYPTO0,
            MUTEX_INIT,
        #if IS_ACTIVE(CONFIG_EFM32_AES_ECB_NONBLOCKING)
            CRYPTO0_IRQn,
            GPIO_PIN(0, 6),
            1,
            0,
            CRYPTO_CTX_INIT
        #endif
        },
    #elif defined(CRYPTO)
        {
            CRYPTO,
            cmuClock_CRYPTO,
            MUTEX_INIT,
        #if IS_ACTIVE(CONFIG_EFM32_AES_ECB_NONBLOCKING)
            CRYPTO_IRQn,
            GPIO_UNDEF,
            3,
            2,
            CRYPTO_CTX_INIT
        #endif
        },
    #endif
    #if defined(CRYPTO1)
        {
            CRYPTO1,
            cmuClock_CRYPTO1,
            MUTEX_INIT,
        #if IS_ACTIVE(CONFIG_EFM32_AES_ECB_NONBLOCKING)
            CRYPTO1_IRQn,
            GPIO_PIN(0, 7),
            3,
            2,
            CRYPTO_CTX_INIT
        #endif
        }
    #endif
};

CRYPTO_TypeDef* crypto_acquire(void) {
    crypto_device_t *crypto = NULL;

    crypto = crypto_acquire_dev();
    return crypto->dev;
}

void crypto_init(void) {
    if (!crypto_lock_initialized) {
        /* initialize lock */
        for (int i = 0; i < CRYPTO_COUNT; i++) {
            mutex_init(&crypto_devs[i].lock);
#if IS_ACTIVE(CONFIG_EFM32_AES_ECB_NONBLOCKING)
            mutex_init(&crypto_devs[i].ctx.sequence_lock);
            mutex_lock(&crypto_devs[i].ctx.sequence_lock);

            NVIC_ClearPendingIRQ(crypto_devs[i].irq);
            NVIC_EnableIRQ(crypto_devs[i].irq);

            LDMA_Init_t ldma_init = LDMA_INIT_DEFAULT;
            LDMA_Init(&ldma_init);

            if (crypto_devs[i].pin != GPIO_UNDEF) {
                gpio_init(crypto_devs[i].pin, GPIO_OUT);
                gpio_clear(crypto_devs[i].pin);
            }
#endif
        }
        crypto_lock_initialized = true;
    }
}

crypto_device_t* crypto_acquire_dev(void) {
    crypto_device_t* dev = NULL;

    for (unsigned i = 0; i < CRYPTO_COUNT; i++) {
        if (mutex_trylock(&crypto_devs[i].lock)) {
            /* found free dev */
            dev = &crypto_devs[i];
            break;
        }
    }

    if (!dev) {
        mutex_lock(&crypto_devs[0].lock);
        dev = &crypto_devs[0];
    }

    CMU_ClockEnable(cmuClock_HFPER, true);
    CMU_ClockEnable(dev->cmu, true);
    return dev;
}

static int get_devno(CRYPTO_TypeDef* dev)
{
    if (CRYPTO_COUNT == 1) {
        return 0;
    }
    else if (CRYPTO_COUNT == 2 && dev == CRYPTO0) {
        return 0;
    }
    else if (CRYPTO_COUNT == 2 && dev == CRYPTO1) {
        return 1;
    }
    return -1;
}

crypto_device_t* crypto_get_dev_by_crypto(CRYPTO_TypeDef* dev)
{
    int devno = get_devno(dev);
    return &crypto_devs[devno];
}

void crypto_release(CRYPTO_TypeDef* dev)
{
    int devno = get_devno(dev);
    if (devno < 0) {
        return;
    }
    crypto_device_t *crypto = &crypto_devs[devno];
    crypto_release_dev(crypto);
}

void crypto_release_dev(crypto_device_t *crypto)
{
    CMU_ClockEnable(crypto->cmu, false);
    mutex_unlock(&crypto->lock);
}

#if IS_ACTIVE(CONFIG_EFM32_AES_ECB_NONBLOCKING)

static inline uint32_t _get_dma_source_and_signal_data0_read(crypto_device_t *crypto)
{
    if (crypto->dev == CRYPTO0) {
        return LDMA_CH_REQSEL_SIGSEL_CRYPTO0DATA0RD | LDMA_CH_REQSEL_SOURCESEL_CRYPTO0;
    }
    else {
        return LDMA_CH_REQSEL_SIGSEL_CRYPTO1DATA0RD | LDMA_CH_REQSEL_SOURCESEL_CRYPTO1;
    }
}

static inline uint32_t _get_dma_source_and_signal_data0_write(crypto_device_t *crypto)
{
    if (crypto->dev == CRYPTO0) {
        return LDMA_CH_REQSEL_SIGSEL_CRYPTO0DATA0WR | LDMA_CH_REQSEL_SOURCESEL_CRYPTO0;
    }
    else {
        return LDMA_CH_REQSEL_SIGSEL_CRYPTO1DATA0WR | LDMA_CH_REQSEL_SOURCESEL_CRYPTO1;
    }
}

static void _init_read_dma_channel(crypto_device_t *crypto, const uint8_t *out)
{
    LDMA->IEN    |= 1UL << (crypto->read_dma_ch);    /* enable DONE interrupt for read channel on LDMA peripheral */
    LDMA->IFC    |= 1UL << (crypto->read_dma_ch);    /* clear DONE interrupt flag of read channel */
    LDMA->CHEN  |= 1UL << (crypto->read_dma_ch);    /* enable DMA read channel */
    LDMA->REQDIS = 0;                              /* enable DMA requests from peripherals */

    /* configure the DMA channel */
    LDMA->CH[crypto->read_dma_ch].CFG = LDMA_CH_CFG_DSTINCSIGN_POSITIVE; /* increment destination address */
    LDMA->CH[crypto->read_dma_ch].REQSEL = _get_dma_source_and_signal_data0_read(crypto);
    LDMA->CH[crypto->read_dma_ch].CTRL  =   LDMA_CH_CTRL_DSTMODE_ABSOLUTE     /* destination address is absolute */
                        | LDMA_CH_CTRL_DSTINC_ONE           /* increment destination address by one units after each write */
                        | LDMA_CH_CTRL_SIZE_BYTE            /* each unit transfer is a byte */
                        | LDMA_CH_CTRL_SRCINC_NONE          /* do not increment the source address */
                        | 15 <<_LDMA_CH_CTRL_XFERCNT_SHIFT  /* transfer 16 units (n + 1) */
                        | LDMA_CH_CTRL_BLOCKSIZE_ALL
                        | LDMA_CH_CTRL_REQMODE_ALL;         /* one transfer request transfers all units defined in XFERCNT */

    LDMA->CH[crypto->read_dma_ch].DST = (uint32_t)out;        /* set destination address to the output buffer */
    LDMA->CH[crypto->read_dma_ch].SRC = (uint32_t)&(crypto->dev->DATA0BYTE); /* set source address to the DATA0 register of the used CRYPTO device */
}

static void _init_write_dma_channel(crypto_device_t *crypto, const uint8_t *in)
{
    LDMA->IEN    |= 1UL << (crypto->write_dma_ch);    /* enable DONE interrupt for write channel on LDMA peripheral */
    LDMA->IFC    |= 1UL << (crypto->write_dma_ch);    /* clear DONE interrupt flag of write channel */
    LDMA->CHEN  |= 1UL << (crypto->write_dma_ch);    /* enable DMA write channel */

    /* configure the DMA channel */
    LDMA->CH[crypto->write_dma_ch].CFG = LDMA_CH_CFG_SRCINCSIGN_POSITIVE; /* increment source address */
    LDMA->CH[crypto->write_dma_ch].REQSEL = _get_dma_source_and_signal_data0_write(crypto);
    LDMA->CH[crypto->write_dma_ch].CTRL  =    LDMA_CH_CTRL_DSTMODE_ABSOLUTE     /* destination address is absolute */
                                            | LDMA_CH_CTRL_SRCINC_ONE           /* increment source address by one units after each write */
                                            | LDMA_CH_CTRL_SIZE_BYTE            /* each unit transfer is a byte */
                                            | LDMA_CH_CTRL_DSTINC_NONE          /* do not increment the destination address */
                                            | 15 <<_LDMA_CH_CTRL_XFERCNT_SHIFT  /* transfer 16 units (n + 1) */
                                            | LDMA_CH_CTRL_REQMODE_ALL;         /* one transfer request transfers all units defined in XFERCNT */

    LDMA->CH[crypto->write_dma_ch].SRC = (uint32_t)in;        /* set source address to the input buffer */
    LDMA->CH[crypto->write_dma_ch].DST = (uint32_t)&(crypto->dev->DATA0BYTE); /* set destination address to the DATA0 register of the used CRYPTO device */
}

static void _init_aes_128_encrypt(crypto_device_t* crypto)
{
    /* configure the CRYPTO device */
    crypto->dev->CTRL =   CRYPTO_CTRL_DMA0RSEL_DATA0 /* use DATA0 register for DMA0RD DMA requests */
                        | CRYPTO_CTRL_DMA0MODE_LENLIMITBYTE  /* read the full target register on every DMA transaction */
                        | CRYPTO_CTRL_AES_AES128;    /* use AES-128 mode */

    //crypto->dev->WAC = 0;
    crypto->dev->SEQCTRL = 16UL; /* NOTE: we want to handle 16 bytes in total per sequence */

    /* enable interrupts on done sequences */
    crypto->dev->IEN |= CRYPTO_IEN_SEQDONE;

    CRYPTO_SEQ_LOAD_3(crypto->dev,
                      CRYPTO_CMD_INSTR_DMA0TODATA,
                      CRYPTO_CMD_INSTR_AESENC,      /* encrypt with AES */
                      CRYPTO_CMD_INSTR_DATATODMA0); /* move from configured DATA register to DMA, request DMA0RD signal */
}

void crypto_aes_128_encrypt(crypto_device_t *crypto, const uint8_t *in,
                            const uint8_t *out, size_t length)
{
    _init_read_dma_channel(crypto, out);
    _init_write_dma_channel(crypto, in);
    _init_aes_128_encrypt(crypto);
    crypto->ctx.sequences = length / AES_SIZE_BYTES;
    crypto->dev->CMD |= CRYPTO_CMD_SEQSTART;
    mutex_lock(&crypto->ctx.sequence_lock);
}

/* called from interrupt to prepare DMA channels for next sequence */
static void _reconfig_dma_from_irq(crypto_device_t *crypto)
{
    LDMA->CHEN |=  (1UL << (crypto->write_dma_ch))
                 | (1UL << (crypto->read_dma_ch));

    LDMA->CH[crypto->write_dma_ch].CTRL |= 15 << _LDMA_CH_CTRL_XFERCNT_SHIFT;

    LDMA->CH[crypto->read_dma_ch].CTRL |= 15 << _LDMA_CH_CTRL_XFERCNT_SHIFT;
}

/* called from interrupts of CRYPTO devices */
static void _crypto_irq(CRYPTO_TypeDef *dev)
{
    crypto_device_t *crypto = crypto_get_dev_by_crypto(dev);

    /* increment the sequence counter */
    crypto->ctx.seq_count++;

    /* if reached the needed amount of sequences signal the mutex */
    if (crypto->ctx.seq_count >= crypto->ctx.sequences) {
        mutex_unlock(&crypto->ctx.sequence_lock);
    }
    /* if not, prepare the DMA for a new sequence and trigger a new encryption */
    else {
        _reconfig_dma_from_irq(crypto);
        crypto->dev->CMD |= CRYPTO_CMD_SEQSTART;
    }
}

void isr_ldma(void)
{
    /* clean interrupt flags */
    LDMA->IFC = 0xFFFFFFFF;
}

void isr_crypto0(void)
{
    /* clean interrupt flags */
    CRYPTO0->IFC = 0xFFFFFFFF;
    _crypto_irq(CRYPTO0);
}

void isr_crypto1(void)
{
    /* clean interrupt flags */
    CRYPTO1->IFC = 0xFFFFFFFF;
    _crypto_irq(CRYPTO1);
}

#endif /* CONFIG_EFM32_AES_ECB_NONBLOCKING */

#endif
