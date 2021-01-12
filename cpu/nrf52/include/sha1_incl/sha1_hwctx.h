#ifndef SHA1_HWCTX_H
#define SHA1_HWCTX_H

#include "cryptocell_incl/crys_hash.h"
#include "kernel_defines.h"

typedef struct {
    CRYS_HASHUserContext_t cc310_ctx;
} sha1_context;

#endif /* SHA1_HWCTX_H */
