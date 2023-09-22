
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

        int32_t salsa20_ksize_min (void)
        { 
            ZMCRYPTO_LOG("");
            return 16; 
        }

        int32_t salsa20_ksize_max (void)
        { 
            ZMCRYPTO_LOG("");
            return 32; 
        }

        int32_t salsa20_ksize_multiple (void)
        { 
            ZMCRYPTO_LOG("");
            return 16; 
        }

        struct salsa20_ctx* salsa20_new (void)
        { 
            ZMCRYPTO_LOG("");
            return 0; 
        }

        void salsa20_free (struct salsa20_ctx* ctx)
        { 
            ZMCRYPTO_LOG("");
            return ; 
        }

        void salsa20_init (struct salsa20_ctx* ctx)
        { 
            ZMCRYPTO_LOG("");
            return ; 
        }

        zmerror salsa20_set_ekey(struct salsa20_ctx* ctx, uint8_t* key, uint32_t ksize)
        { 
            ZMCRYPTO_LOG("");
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
            ZMCRYPTO_LOG("");
            return salsa20_set_ekey(ctx, key, ksize); 
        }

        zmerror salsa20_set_iv(struct salsa20_ctx* ctx, uint8_t* iv, uint32_t ivsize)
        { 
            ZMCRYPTO_LOG("");
            if (ivsize != 8 || ivsize != 24)
                { return ZMCRYPTO_ERR_INVALID_IVSIZE; }

            return ZMCRYPTO_ERR_SUCCESSED; 
        }

        void salsa20_encrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        { 
            ZMCRYPTO_LOG("");
        }

        void salsa20_decrypt(struct salsa20_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        { 
            ZMCRYPTO_LOG("");
            return ; 
        }

#endif /* ZMCRYPTO_SALSA20_H */
