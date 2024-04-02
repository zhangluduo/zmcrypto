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

#include "tea.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_TEA

        struct tea_ctx
        {
            uint8_t key[16];
        } ;

        /* private function begin */
        void tea_encrypt(uint32_t *v, uint32_t *k)
        {
            uint32_t y = v[0], z = v[1], sum = 0, i;           // set up
            uint32_t delta = 0x9e3779b9;                       // a key schedule constant
            uint32_t a = k[0], b = k[1], c = k[2], d = k[3];   // cache key
            for (i = 0; i < 32; i++)                           // basic cycle start
            {
                sum += delta;
                y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
                z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d); // end cycle
            }
            v[0] = y;
            v[1] = z;
        }


        void tea_decrypt(uint32_t*v, uint32_t *k)
        {
            uint32_t y = v[0], z = v[1], sum = 0xC6EF3720, i;  // set up
            uint32_t delta = 0x9e3779b9;                       // a key schedule constant
            uint32_t a = k[0], b = k[1], c = k[2], d = k[3];    // cache key
            for(i = 0; i < 32; i++)                            // basic cycle start
            {
                z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
                y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
                sum -= delta;                                       // end cycle
            }
            v[0] = y;
            v[1] = z;
        }
        /* private function end */

        struct tea_ctx* tea_new (void)
        {
            struct tea_ctx* ctx = (struct tea_ctx*)zmcrypto_malloc(sizeof(struct tea_ctx));
            zmcrypto_memset(ctx, 0, sizeof(struct tea_ctx));
            return ctx;
        };

        void tea_free (struct tea_ctx* ctx)
        {
            zmcrypto_free(ctx);
        }

        void tea_init (struct tea_ctx* ctx) 
        {
            zmcrypto_memset(ctx, 0, sizeof(struct tea_ctx));
        }

        int32_t tea_block_size(void)
            { return 8; }

        int32_t tea_ksize_min(void)
            { return 16; }

        int32_t tea_ksize_max(void)
            { return 16; }

        int32_t tea_ksize_multiple(void)
            { return 16; }

        zmerror tea_set_ekey(struct tea_ctx* ctx, uint8_t* key, uint32_t ksize) 
        { 
            if (ksize != 16) { return ZMCRYPTO_ERR_INVALID_KSIZE; };
            (void)zmcrypto_memcpy(ctx->key, key, ksize);
            return ZMCRYPTO_ERR_SUCCESSED; 
        }

        zmerror tea_set_dkey(struct tea_ctx* ctx, uint8_t* key, uint32_t ksize) 
        { 
            if (ksize != 16) { return ZMCRYPTO_ERR_INVALID_KSIZE; };
            (void)zmcrypto_memcpy(ctx->key, key, ksize);
            return ZMCRYPTO_ERR_SUCCESSED; 
        }

        void tea_enc_block(struct tea_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        {
            unsigned int key[4];
            uint32_t in[2];
            GET_UINT32_BE(key[0], ctx->key, 0);
            GET_UINT32_BE(key[1], ctx->key, 4);
            GET_UINT32_BE(key[2], ctx->key, 8);
            GET_UINT32_BE(key[3], ctx->key, 12);
            
            GET_UINT32_BE(in[0], plaintext, 0);
            GET_UINT32_BE(in[1], plaintext, 4);

            tea_encrypt(in, key);

            PUT_UINT32_BE(in[0], ciphertext, 0);
            PUT_UINT32_BE(in[1], ciphertext, 4);
        }

        void tea_dec_block(struct tea_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext)
        {
            unsigned int key[4];
            uint32_t in[2];
            GET_UINT32_BE(key[0], ctx->key, 0);
            GET_UINT32_BE(key[1], ctx->key, 4);
            GET_UINT32_BE(key[2], ctx->key, 8);
            GET_UINT32_BE(key[3], ctx->key, 12);
            
            GET_UINT32_BE(in[0], ciphertext, 0);
            GET_UINT32_BE(in[1], ciphertext, 4);

            tea_decrypt(in, key);
            
            PUT_UINT32_BE(in[0], plaintext, 0);
            PUT_UINT32_BE(in[1], plaintext, 4);
        }

    #endif

#ifdef  __cplusplus
}
#endif
