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
 *   Date: Mar. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "xtea.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_XTEA
        struct xtea_ctx
        {
            uint32_t k[4];       /*!< key */
        } ;
        
        struct xtea_ctx* xtea_new (void)
        {
            struct xtea_ctx* ctx = (struct xtea_ctx*)zmcrypto_malloc(sizeof(struct xtea_ctx));
            zmcrypto_memset(ctx, 0, sizeof(struct xtea_ctx));
            return ctx;
        };

        void xtea_free (struct xtea_ctx* ctx)
            { zmcrypto_free(ctx); }

        void xtea_init (struct xtea_ctx* ctx)
            { zmcrypto_memset(ctx, 0, sizeof(struct xtea_ctx)); }

        int32_t xtea_block_size(void)     { return  8; }
        int32_t xtea_ksize_min(void)      { return 16; }
        int32_t xtea_ksize_max(void)      { return 16; }
        int32_t xtea_ksize_multiple(void) { return 16; }

        zmerror xtea_set_ekey(struct xtea_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            if (ksize != 16)
                { return ZMCRYPTO_ERR_INVALID_KSIZE; }

            for(uint32_t i = 0; i < 4U; i++ )
                { GET_UINT32_BE( ctx->k[i], key, i << 2 ); }

            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror xtea_set_dkey(struct xtea_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            return xtea_set_ekey(ctx, key, ksize);
        }

        void xtea_enc_block(struct xtea_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        {
            uint32_t *k, v0, v1, i;

            k = ctx->k;

            GET_UINT32_BE( v0, plaintext, 0 );
            GET_UINT32_BE( v1, plaintext, 4 );

            uint32_t sum = 0, delta = 0x9E3779B9;

            for( i = 0; i < 32; i++ )
            {
                v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
                sum += delta;
                v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
            }

            PUT_UINT32_BE( v0, ciphertext, 0 );
            PUT_UINT32_BE( v1, ciphertext, 4 );
        }

        void xtea_dec_block(struct xtea_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext)
        {
            uint32_t *k, v0, v1, i;

            k = ctx->k;

            GET_UINT32_BE( v0, ciphertext, 0 );
            GET_UINT32_BE( v1, ciphertext, 4 );

            uint32_t delta = 0x9E3779B9, sum = delta * 32;

            for( i = 0; i < 32; i++ )
            {
                v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
                sum -= delta;
                v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
            }

            PUT_UINT32_BE( v0, plaintext, 0 );
            PUT_UINT32_BE( v1, plaintext, 4 );
        }

    #endif

#ifdef  __cplusplus
}
#endif
