#include "stdio.h"
#include "string.h"

#include <mini_aes.h>
#include <Config.h>

#define MINI_AES_DEBUG

#ifdef MINI_AES_DEBUG
#define mini_aes_log(...)   fprintf(stdout, __VA_ARGS__)
#else
#define mini_aes_log(...)
#endif

MINI_AES_ERR_T mini_aes_init(mini_aes_context *ctx)
{
    if (!ctx)
    {
        mini_aes_log("%s ctx is NULL\n", __func__);
        return MINI_AES_ERR_INVALID_PARAM;
    }

    ctx->round = MINI_AES_ROUND;

    return MINI_AES_OK;
}

MINI_AES_ERR_T mini_aes_free(mini_aes_context *ctx)
{
    if (!ctx)
    {
        mini_aes_log("%s ctx is NULL\n", __func__);
        return MINI_AES_ERR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(mini_aes_context));

    return MINI_AES_OK;
}

MINI_AES_ERR_T mini_aes_setkey(mini_aes_context *ctx, uint8_t* keyPtr, uint8_t len)
{
    if (!ctx || !keyPtr)
    {
        mini_aes_log("%s ctx or keyPtr is NULL\n", __func__);
        return MINI_AES_ERR_INVALID_PARAM;
    }

    /* set key and advoid all zero key */
    uint8_t* ctxKeyPtr = (uint8_t*)ctx->key;
    uint8_t ctxKeyLen = sizeof(((mini_aes_context *)0)->key)  - 1;
    len = len < ctxKeyLen? len: ctxKeyLen;
    memset(ctxKeyPtr, (ctxKeyLen - len) & 0xFF, ctxKeyLen);
    memcpy(ctxKeyPtr, keyPtr, len);
    ctxKeyPtr[ctxKeyLen] = len;

    return MINI_AES_OK;
}

int is_big_endian(void)
{
    union {
        uint32_t i;
        char c[4];
    } e = { 0x01000000 };

    return e.c[0];
}

static void mini_aes_enc_run(uint8_t* a, uint8_t* b, 
    uint8_t* c, uint8_t* d, 
    uint32_t rk)
{
    /* xor */
    uint8_t* rkp = (uint8_t*) &rk;

    *a ^= rkp[0];
    *b ^= rkp[1];
    *c ^= rkp[2];
    *d ^= rkp[3];

    /* mix */
    uint8_t e, f, g, h;
    e = *a;
    f = *b;
    g = *c;
    h = *d;

    *a = (e & 0xC0) | (f & 0x30) | (g & 0x0C) | (h & 0x03);
    *b = (f & 0xC0) | (g & 0x30) | (h & 0x0C) | (e & 0x03);
    *c = (g & 0xC0) | (h & 0x30) | (e & 0x0C) | (f & 0x03);
    *d = (h & 0xC0) | (e & 0x30) | (f & 0x0C) | (g & 0x03);
    // reset temp
    e = f = g = h = 0;

    /* s-box */
    *a = ((*a) << 4) + ((*a) << 3) + ((*a) << 1) + (*a);
    *b = ((*b) << 4) + ((*b) << 3) + ((*b) << 1) + (*b);
    *c = ((*c) << 4) + ((*c) << 3) + ((*c) << 1) + (*c);
    *d = ((*d) << 4) + ((*d) << 3) + ((*d) << 1) + (*d);
}

MINI_AES_ERR_T mini_aes_enc(mini_aes_context *ctx, uint32_t* in, uint32_t* out)
{
    if (!ctx || !in || !out)
    {
        mini_aes_log("%s ctx or in or out is NULL\n", __func__);
        return MINI_AES_ERR_INVALID_PARAM;
    }

    /* parse in */
    uint8_t a, b, c , d;
    uint8_t* dataPtr = (uint8_t*) in;
    // check big endian
    if (is_big_endian())
    {
        a = dataPtr[0]; b = dataPtr[1]; c = dataPtr[2]; d = dataPtr[3]; 
    }
    else
    {
        a = dataPtr[3]; b = dataPtr[2]; c = dataPtr[1]; d = dataPtr[0]; 
    }

    /* run round */
    for (int i = 0; i < MINI_AES_ROUND; i++)
    {
        mini_aes_enc_run(&a, &b, &c, &d, ctx->key[i]);
    }

    /* merge out */
    dataPtr = (uint8_t*) out;
    dataPtr[0] = a; dataPtr[1] = b; dataPtr[2] = c; dataPtr[3] = d;

    /* reset temp */
    a = b = c = d = 0;

    return MINI_AES_OK;
}

static void mini_aes_dec_run(uint8_t* a, uint8_t* b, 
    uint8_t* c, uint8_t* d, 
    uint32_t rk)
{
    /* s-box */
    *a = ((*a) << 4) + ((*a) << 1) + (*a);
    *b = ((*b) << 4) + ((*b) << 1) + (*b);
    *c = ((*c) << 4) + ((*c) << 1) + (*c);
    *d = ((*d) << 4) + ((*d) << 1) + (*d);

    /* mix */
    uint8_t e, f, g, h;
    e = *a;
    f = *b;
    g = *c;
    h = *d;

    *a = (e & 0xC0) | (h & 0x30) | (g & 0x0C) | (f & 0x03);
    *b = (f & 0xC0) | (e & 0x30) | (h & 0x0C) | (g & 0x03);
    *c = (g & 0xC0) | (f & 0x30) | (e & 0x0C) | (h & 0x03);
    *d = (h & 0xC0) | (g & 0x30) | (f & 0x0C) | (e & 0x03);
    // reset temp
    e = f = g = h = 0; 

    /* xor */
    uint8_t* rkp = (uint8_t*) &rk;

    *a ^= rkp[0];
    *b ^= rkp[1];
    *c ^= rkp[2];
    *d ^= rkp[3];
}

MINI_AES_ERR_T mini_aes_dec(mini_aes_context *ctx, uint32_t* in, uint32_t* out)
{
    if (!ctx || !in || !out)
    {
        mini_aes_log("%s ctx or in or out is NULL\n", __func__);
        return MINI_AES_ERR_INVALID_PARAM;
    }

    /* parse in */
    uint8_t a, b, c , d;
    uint8_t* dataPtr = (uint8_t*) in;
    a = dataPtr[0]; b = dataPtr[1]; c = dataPtr[2]; d = dataPtr[3]; 

    /* run round */
    for (int i = MINI_AES_ROUND - 1; i >= 0 ; i--)
    {
        mini_aes_dec_run(&a, &b, &c, &d, ctx->key[i]);
    }

    /* merge out */
    dataPtr = (uint8_t*) out;
    if (is_big_endian())
    {
        dataPtr[0] = a; dataPtr[1] = b; dataPtr[2] = c; dataPtr[3] = d;
    }
    else
    {
        dataPtr[3] = a; dataPtr[2] = b; dataPtr[1] = c; dataPtr[0] = d;
    }

    /* reset temp */
    a = b = c = d = 0;

    return MINI_AES_OK;
}

#define ERR_OUT(ret) \
if (ret != MINI_AES_OK) \
{ mini_aes_log("Error out at line %d\n", __LINE__); }

static uint32_t str2uint32(char *string)
{
    uint32_t ret = 0;
    int len = strlen(string);
    if (len > 2 && string[0] == '0' && (string[1] == 'x' || string[1] == 'X'))
    {
        for (int i = 2; i < len; i++)
        {
            if (string[i] >= '0' && string[i] <= '9')
            {
                ret = ret * 16 + (string[i] - '0');
            }
            else if (string[i] >= 'a' && string[i] <= 'f')
            {
                ret = ret * 16 + 10 + (string[i] - 'a');
            }
            else if (string[i] >= 'A' && string[i] <= 'F')
            {
                ret = ret * 16 + 10 + (string[i] - 'A');
            }
            else
            {
                ret = ret * 16;
            }
        }
    }
    else if (len > 2 && string[0] == '0' && (string[1] == 'h' || string[1] == 'H'))
    {
        for (int i = 2; i < len; i++)
        {
            if (string[i] >= '0' && string[i] <= '7')
            {
                ret = ret * 8 + (string[i] - '0');
            }
            else
            {
                ret = ret * 8;
            }
        }
    }
    else if (len > 2 && string[0] == '0' && (string[1] == 'b' || string[1] == 'B'))
    {
        for (int i = 2; i < len; i++)
        {
            if (string[i] >= '0' && string[i] <= '1')
            {
                ret = (ret << 1) + (string[i] - '0');
            }
            else
            {
                ret = ret << 1;
            }
        }
    }
    else if (len > 2 && string[0] == '0' && (string[1] == 'd' || string[1] == 'D'))
    {
        for (int i = 2; i < len; i++)
        {
            if (string[i] >= '0' && string[i] <= '9')
            {
                ret = ret * 10 + (string[i] - '0');
            }
            else
            {
                ret = ret * 10;
            }
        }
    }
    else
    {
        for (int i = 0; i < len; i++)
        {
            if (string[i] >= '0' && string[i] <= '9')
            {
                ret = ret * 10 + (string[i] - '0');
            }
            else
            {
                ret = ret * 10;
            }
        }
    }
    
    return ret;
}

#define DEFAULT_IN  (0x12345678)
#define DEFAULT_KEY "abcdefghijklmnopqrstuvwxyz"

void main(int argc, char** argv)
{
    uint32_t in, out;
    if (argc > 1)
    {
        in = str2uint32(argv[1]);
    }
    else
    {
        in = DEFAULT_IN;
    }

    MINI_AES_ERR_T ret = MINI_AES_ERR_END;
    mini_aes_context ctx;
    ret = mini_aes_init(&ctx);
    ERR_OUT(ret);
    if (argc > 2)
    {
        ret = mini_aes_setkey(&ctx, argv[2], strlen(argv[2]));
    } 
    else
    {
        ret = mini_aes_setkey(&ctx, DEFAULT_KEY, strlen(DEFAULT_KEY));
    }
    ERR_OUT(ret);
    ret = mini_aes_enc(&ctx, &in, &out);
    ERR_OUT(ret);
    mini_aes_log("enc out is %08x\n", out);
    ret = mini_aes_dec(&ctx, &out, &in);
    ERR_OUT(ret);
    mini_aes_log("dec out is %08x\n", in);
    ret = mini_aes_free(&ctx);
    ERR_OUT(ret);
}