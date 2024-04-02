
/**
 *  Copyright 2022 The ZmCrypto Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * 
 * Author: Zhang Luduo (zhangluduo@qq.com)
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "salsa20.h"
#include "debug.h"

#if defined ZMCRYPTO_SALSA20_H

    typedef struct salsa20_ctx
    {
        uint32_t state[16];
        uint8_t buffer[64];
        uint32_t position;
    } xsalsa20_ctx;

    /* PRIVATE BEGIN */

    #define SALSA20_QUARTER_ROUND(x1, x2, x3, x4)\
        do {                                     \
        x2 ^= ROTL(x1 + x4,  7);                 \
        x3 ^= ROTL(x2 + x1,  9);                 \
        x4 ^= ROTL(x3 + x2, 13);                 \
        x1 ^= ROTL(x4 + x3, 18);                 \
        } while(0)

    /* PRIVATE END */

    int32_t salsa20_ksize_min (void)
    { 
        return 16; 
    }

    int32_t salsa20_ksize_max (void)
    { 
        return 32; 
    }

    int32_t salsa20_ksize_multiple (void)
    { 
        return 16; 
    }

    struct salsa20_ctx* salsa20_new (void)
    { 
        return 0; 
    }

    void salsa20_free (struct salsa20_ctx* ctx)
    { 
        return ; 
    }

    void salsa20_init (struct salsa20_ctx* ctx)
    { 
        return ; 
    }

    zmerror salsa20_set_ekey(struct salsa20_ctx* ctx, uint8_t* key, uint32_t ksize)
    { 
        if (ksize != 16 && ksize != 32)
            { return ZMCRYPTO_ERR_INVALID_KSIZE; }

        static const uint32_t TAU[] =
            { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

        static const uint32_t SIGMA[] =
            { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

        const uint32_t* CONSTANTS = (ksize == 16) ? TAU : SIGMA;

        ctx->state[0] = CONSTANTS[0];
        ctx->state[5] = CONSTANTS[1];
        ctx->state[10] = CONSTANTS[2];
        ctx->state[15] = CONSTANTS[3];

        #if defined ENDIAN_LITTLE
            GET_UINT32_LE(ctx->state[1], key, 0);
            GET_UINT32_LE(ctx->state[2], key, 4);
            GET_UINT32_LE(ctx->state[3], key, 8);
            GET_UINT32_LE(ctx->state[4], key, 12);

            if(ksize == 32)
            {
                GET_UINT32_LE(ctx->state[11], key, 16);
                GET_UINT32_LE(ctx->state[12], key, 20);
                GET_UINT32_LE(ctx->state[13], key, 24);
                GET_UINT32_LE(ctx->state[14], key, 28);
            }
        #else
            #error no implemention here
        #endif
/*
        printf ("ctx->state: ");
        for (int i = 0; i < 16; i++){
            printf ("%08x ", ctx->state[i]);
        }  printf ("\n");
*/
        return ZMCRYPTO_ERR_SUCCESSED; 
    }

    zmerror salsa20_set_dkey(struct salsa20_ctx* ctx, uint8_t* key, uint32_t ksize)
    { 
        return salsa20_set_ekey(ctx, key, ksize); 
    }

    zmerror salsa20_set_iv(struct salsa20_ctx* ctx, uint8_t* iv)
    { 
        return ZMCRYPTO_ERR_SUCCESSED; 
    }

    void salsa20_encrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
    { 
    }

    void salsa20_decrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
    { 
        return ; 
    }

    int32_t xsalsa20_ksize_min (void) {return 0;}
    int32_t xsalsa20_ksize_max (void) {return 0;}
    int32_t xsalsa20_ksize_multiple (void) {return 0;}
    struct xsalsa20_ctx* xsalsa20_new (void) {return 0;}
    void xsalsa20_free (struct xsalsa20_ctx* ctx) {return;}
    void xsalsa20_init (struct xsalsa20_ctx* ctx){return;}
    zmerror xsalsa20_set_ekey(struct xsalsa20_ctx* ctx, uint8_t* key, uint32_t ksize){return 0;}
    zmerror xsalsa20_set_dkey(struct xsalsa20_ctx* ctx, uint8_t* key, uint32_t ksize){return 0;}
    zmerror xsalsa20_set_iv(struct xsalsa20_ctx* ctx, uint8_t* iv){return 0;}
    void xsalsa20_encrypt(struct xsalsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output){return;}
    void xsalsa20_decrypt(struct xsalsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output){return;}
    
#endif /* ZMCRYPTO_SALSA20_H */
