#ifndef CRYPTOCELL_UTIL_H
#define CRYPTOCELL_UTIL_H

/**
 * Enables CryptoCell module and IRQs on nrf52840.
 * Must be called before using crypto functions.
 */
void cryptocell_enable(void);

/**
 * Disables CryptoCell module and IRQs on nrf52840.
 * Should be called after using crypto functions.
 */
void cryptocell_disable(void);

#endif /* CRYPTOCELL_UTIL */