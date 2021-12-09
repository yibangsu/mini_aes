#ifndef __MINI_AES_H__
#define __MINI_AES_H__

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MINI_AES_ENC    0
#define MINI_AES_DEC    1

#define MINI_AES_ROUND  8

typedef enum {
    MINI_AES_OK = 0,
    MINI_AES_ERR_INVALID_PARAM,
    MINI_AES_ERR_END,
} MINI_AES_ERR_T;

typedef struct
{
    uint8_t round;
    uint32_t key[MINI_AES_ROUND];
} mini_aes_context;

MINI_AES_ERR_T mini_aes_init(mini_aes_context *ctx);
MINI_AES_ERR_T mini_aes_free(mini_aes_context *ctx);
MINI_AES_ERR_T mini_aes_setkey(mini_aes_context *ctx, uint8_t* keyPtr, uint8_t len);
MINI_AES_ERR_T mini_aes_enc(mini_aes_context *ctx, uint32_t* in, uint32_t* out);
MINI_AES_ERR_T mini_aes_dec(mini_aes_context *ctx, uint32_t* in, uint32_t* out);

#ifdef __cplusplus
}
#endif

#endif // __MINI_AES_H__