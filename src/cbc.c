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

#include "cbc.h"

#if defined ZMCRYPTO_ALGO_CBC

        void cbc_init (struct cbc_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* init),
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

        struct cbc_ctx* cbc_new(void)
        {
            struct cbc_ctx* ctx = (struct cbc_ctx*)zmcrypto_malloc(sizeof(struct cbc_ctx));
            zmcrypto_memset(ctx, 0, sizeof(struct cbc_ctx));
            return ctx;
        }

        void cbc_free (struct cbc_ctx* ctx)
        {
            if (ctx->cipher_ctx){
                ctx->cipher_free(ctx->cipher_ctx);
            }
            zmcrypto_free (ctx);
            ctx = NULL;
        }

        zmerror cbc_set_ekey (struct cbc_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)
        {
            if (!(ctx->cipher_ctx)){
                ctx->cipher_ctx = ctx->cipher_new();
            }

            if (ctx->cipher_block_size() != ivsize){
                return ZMCRYPTO_ERR_INVALID_IVSIZE;
            }

            zmcrypto_memcpy(ctx->iv, iv, ivsize);

            if (ctx->cipher_set_ekey(ctx->cipher_ctx, key, ksize) <= 0){
                return ZMCRYPTO_ERR_INVALID_KSIZE;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror cbc_set_dkey (struct cbc_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)
        {
            if (!(ctx->cipher_ctx)){
                ctx->cipher_ctx = ctx->cipher_new();
            }

            if (ctx->cipher_block_size() != ivsize){
                return ZMCRYPTO_ERR_INVALID_IVSIZE;
            }

            zmcrypto_memcpy(ctx->iv, iv, ivsize);

            if (ctx->cipher_set_dkey(ctx->cipher_ctx, key, ksize) <= 0){
                return ZMCRYPTO_ERR_INVALID_KSIZE;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        /*
        CT := ENC(PT ^ IV, KEY);
        IV := CT; // update IV
        */
        zmerror cbc_enc (struct cbc_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            int32_t blocksize = ctx->cipher_block_size();
            if (ilen == 0 || blocksize <= 0 || ilen % blocksize != 0){
                return ZMCRYPTO_ERR_INVALID_DSIZE;
            }

            uint32_t blockcount = ilen / blocksize;

            for (uint32_t i = 0; i < blockcount; i++){
                uint8_t* p = input + i * blocksize;
                for (int32_t j = 0; j < blocksize; j++){
                    ctx->temp[j] = ctx->iv[j] ^ p[j];
                }
                ctx->cipher_enc_block (ctx->cipher_ctx, ctx->temp, output + i * blocksize);
                zmcrypto_memcpy(ctx->iv, output + i * blocksize, blocksize);
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        /*
        PT := DEC(KEY, CT) ^ IV;
        IV := PT; // update IV
        */
        zmerror cbc_dec (struct cbc_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            int32_t blocksize = ctx->cipher_block_size();
            if (ilen == 0 || blocksize <= 0 || ilen % blocksize != 0){
                return ZMCRYPTO_ERR_INVALID_DSIZE;
            }

            uint32_t blockcount = ilen / blocksize;
            for (uint32_t i = 0; i < blockcount; i++){
                uint8_t* p = input + i * blocksize;
                ctx->cipher_dec_block (ctx->cipher_ctx, p, ctx->temp);
                for (int32_t j = 0; j < blocksize; j++){
                    (output + i * blocksize)[j] = (ctx->temp[j] ^ ctx->iv[j]);
                }
                zmcrypto_memcpy(ctx->iv, p, blocksize);
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

#endif /* ZMCRYPTO_ALGO_CBC */
