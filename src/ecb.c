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
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "ecb.h"

#if defined ZMCRYPTO_ALGO_ECB

        void ecb_init (struct ecb_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* ctx),
            int32_t (*cipher_block_size)     (void),
            int32_t (*cipher_ksize_min)      (void),
            int32_t (*cipher_ksize_max)      (void),
            int32_t (*cipher_ksize_multiple) (void),
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
            int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize),
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext),
            void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext)
        )
        {
            ctx->cipher_new            = cipher_new            ;
            ctx->cipher_free           = cipher_free           ;
            ctx->cipher_init           = cipher_init           ;
            ctx->cipher_block_size     = cipher_block_size     ;
            ctx->cipher_ksize_min      = cipher_ksize_min      ;
            ctx->cipher_ksize_max      = cipher_ksize_max      ;
            ctx->cipher_ksize_multiple = cipher_ksize_multiple ;
            ctx->cipher_set_ekey       = cipher_set_ekey       ;
            ctx->cipher_set_dkey       = cipher_set_dkey       ;
            ctx->cipher_enc_block      = cipher_enc_block      ;
            ctx->cipher_dec_block      = cipher_dec_block      ;
            ctx->cipher_ctx            = NULL;
        }

        struct ecb_ctx* ecb_new (void)
        {
            struct ecb_ctx* ctx = (struct ecb_ctx*)zmcrypto_malloc(sizeof(struct ecb_ctx));
            zmcrypto_memset(ctx, 0, sizeof(struct ecb_ctx));
            return ctx;
        }

        void ecb_free (struct ecb_ctx* ctx)
        {
            if (ctx->cipher_ctx){
                ctx->cipher_free(ctx->cipher_ctx);
            }
            zmcrypto_free (ctx);
            ctx = NULL;
        }

        zmerror ecb_set_ekey (struct ecb_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            if (!(ctx->cipher_ctx)){
                ctx->cipher_ctx = ctx->cipher_new();
            }

            if (ctx->cipher_set_ekey(ctx->cipher_ctx, key, ksize) <= 0){
                return ZMCRYPTO_ERR_INVALID_KSIZE;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }
        
        zmerror ecb_set_dkey (struct ecb_ctx* ctx, uint8_t* key, uint32_t ksize)
        {
            if (!(ctx->cipher_ctx)){
                ctx->cipher_ctx = ctx->cipher_new();
            }

            if (ctx->cipher_set_dkey(ctx->cipher_ctx, key, ksize) <= 0){
                return ZMCRYPTO_ERR_INVALID_KSIZE;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror ecb_enc (struct ecb_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            int32_t blocksize = ctx->cipher_block_size();
            if (ilen == 0 || blocksize <= 0 || ilen % blocksize != 0){
                return ZMCRYPTO_ERR_INVALID_DSIZE;
            }

            uint32_t blockcount = ilen / blocksize;
            for (uint32_t i = 0; i < blockcount; i++){
                ctx->cipher_enc_block (ctx->cipher_ctx, input + i * blocksize, output + i * blocksize);
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror ecb_dec (struct ecb_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            int32_t blocksize = ctx->cipher_block_size();
            if (ilen == 0 || blocksize <= 0 || ilen % blocksize != 0){
                return ZMCRYPTO_ERR_INVALID_DSIZE;
            }

            uint32_t blockcount = ilen / blocksize;
            for (uint32_t i = 0; i < blockcount; i++){
                ctx->cipher_dec_block (ctx->cipher_ctx, input + i * blocksize, output + i * blocksize);
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

#endif /* ZMCRYPTO_ALGO_ECB */
