include ../Makefile.tests_common

# Default stack with printf + the tests buffer uint32_t[32]/uint8_t[256]
MAIN_THREAD_SIZE = THREAD_STACKSIZE_DEFAULT+1024+1024
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\($(MAIN_THREAD_SIZE)\)

# override PRNG if desired (see sys/random for alternatives)
# USEMODULE += prng_minstd

USEMODULE += fmt
USEMODULE += random
USEMODULE += shell
USEMODULE += xtimer

FEATURES_OPTIONAL += periph_hwrng

ifeq (pba-d-01-kw2x, $(BOARD))
	# Kinetis Hardware
	CFLAGS += -DFREESCALE_MMCAU -Wno-unused-function
	USEMODULE += lib_mmcau
endif

ifeq (frdm-k64f, $(BOARD))
	# Kinetis Hardware
	CFLAGS += -DFREESCALE_MMCAU -Wno-unused-function
	USEMODULE += lib_mmcau
endif

ifeq (nrf52840dk, $(BOARD))
	CFLAGS += -DARM_CRYPTOCELL
	USEMODULE += lib_cryptocell
endif

TEST_ON_CI_WHITELIST += native

export TEST_KCONFIG ?= 1

include $(RIOTBASE)/Makefile.include
