
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

#include "rc4.h"
#include "debug.h"

#if defined ZMCRYPTO_ALGO_RC4

        struct rc4_ctx
        {
            uint32_t x;     /*!< permutation index */
            uint32_t y;     /*!< permutation index */
            uint8_t m[256]; /*!< permutation table */
        } ;
        
        int32_t rc4_ksize_min (void){ return 1; }
        int32_t rc4_ksize_max (void){ return 256; }
        int32_t rc4_ksize_multiple (void){ return 1; }

        struct rc4_ctx* rc4_new (void)
        {
            ZMCRYPTO_LOG("");
            struct rc4_ctx* ctx = (struct rc4_ctx*)zmcrypto_malloc(sizeof(struct rc4_ctx));
            return ctx;
        }

        void rc4_free (struct rc4_ctx* ctx)
        {
            ZMCRYPTO_LOG("");
            zmcrypto_free(ctx);
        }

        void rc4_init (struct rc4_ctx* ctx)
        {
            ZMCRYPTO_LOG("");
            zmcrypto_memset(ctx, 0, sizeof(struct rc4_ctx));
        }

        zmerror rc4_set_ekey(struct rc4_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            ZMCRYPTO_LOG("");
            if (!(ksize >= 1 && ksize <= 256)) { return ZMCRYPTO_ERR_INVALID_KSIZE; }

            uint32_t i, j, a;
            uint8_t k;
            uint8_t* m;

            ctx->x = 0;
            ctx->y = 0;
            m = ctx->m;

            for (i = 0; i < 256; i++)
            {
                m[i] = (uint8_t) i;
            }

            j = k = 0;

            for( i = 0; i < 256; i++, k++ )
            {
                if( k >= ksize ) { k = 0; }

                a = m[i];
                j = (j + a + key[k]) & 0xFF;
                m[i] = m[j];
                m[j] = (uint8_t) a;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror rc4_set_dkey(struct rc4_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            ZMCRYPTO_LOG("");
            return rc4_set_ekey(ctx, key, ksize);
        }

        void rc4_encrypt(struct rc4_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            ZMCRYPTO_LOG("");
            uint32_t x, y, a, b;
            uint32_t i;
            uint8_t* m;

            x = ctx->x;
            y = ctx->y;
            m = ctx->m;

            for (i = 0; i < ilen; i++)
            {
                x = (x + 1) & 0xFF; a = m[x];
                y = (y + a) & 0xFF; b = m[y];

                m[x] = (uint8_t) b;
                m[y] = (uint8_t) a;

                output[i] = (uint8_t)(input[i] ^ m[(uint8_t)(a + b)]);
            }

            ctx->x = x;
            ctx->y = y;
        }

        void rc4_decrypt(struct rc4_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            ZMCRYPTO_LOG("");
            rc4_encrypt(ctx, input, ilen, output);
        }

#endif /* ZMCRYPTO_ALGO_RC4 */
