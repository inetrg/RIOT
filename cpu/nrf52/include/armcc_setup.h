#ifndef ARMCC_SETUP_H
#define ARMCC_SETUP_H

/**
 * Enables CryptoCell module, IRQs and crypto libraries on nrf52840.
 * Must be called once before using the CryptoCell lib.
 */
void cryptocell_setup(void);

/**
 * Finishes the use of the CryptoCell library.
 * Should be called after using the CryptoCell lib.
 */
void cryptocell_terminate(void);

#endif /*ARMCC_SETUP_H*/