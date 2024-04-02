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
 *   Date: Nov. 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "ctr.h"

#if defined ZMCRYPTO_ALGO_CTR

        struct ctr_ctx
        {
            void*   (*cipher_new)            (void);
            void    (*cipher_free)           (void* ctx);
            void    (*cipher_init)           (void* ctx);
            int32_t (*cipher_block_size)     (void);
            int32_t (*cipher_ksize_min)      (void);
            int32_t (*cipher_ksize_max)      (void);
            int32_t (*cipher_ksize_multiple) (void);
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);

            void* cipher_ctx;
            uint32_t nc_offset; /* offset of nonce counter */
            uint8_t nonce_counter[ZMCRYPTO_MAX_IVSIZE];
            uint8_t temp[ZMCRYPTO_MAX_IVSIZE];
        } ;

        void ctr_init (struct ctr_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* ctx),
            int32_t (*cipher_block_size)     (void),
            int32_t (*cipher_ksize_min)      (void),
            int32_t (*cipher_ksize_max)      (void),
            int32_t (*cipher_ksize_multiple) (void),
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
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
            ctx->cipher_enc_block      = cipher_enc_block      ;
            ctx->cipher_ctx            = NULL;
            ctx->nc_offset             = 0;
        }

		struct ctr_ctx* ctr_new(void)
        { 
            struct ctr_ctx* ctx = (struct ctr_ctx*)zmcrypto_malloc(sizeof(struct ctr_ctx));
            zmcrypto_memset(ctx, 0, sizeof(struct ctr_ctx));
            return ctx;
        }

        void ctr_free (struct ctr_ctx* ctx)
        {
            if (ctx->cipher_ctx){
                ctx->cipher_free(ctx->cipher_ctx);
                ctx->cipher_ctx = NULL;
            }
            zmcrypto_free (ctx);
        }

        zmerror ctr_set_ekey (struct ctr_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* nonce_counter, uint32_t ncsize)
        {
            if (!(ctx->cipher_ctx)){
                ctx->cipher_ctx = ctx->cipher_new();
            }

            if (ctx->cipher_block_size() != ncsize){
                return ZMCRYPTO_ERR_INVALID_IVSIZE;
            }

            zmcrypto_memcpy(ctx->nonce_counter, nonce_counter, ncsize);

            if (ctx->cipher_set_ekey(ctx->cipher_ctx, key, ksize) <= 0){
                return ZMCRYPTO_ERR_INVALID_KSIZE;
            }
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        zmerror ctr_set_dkey (struct ctr_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* nonce_counter, uint32_t ncsize)
        {
            return ctr_set_ekey (ctx, key, ksize, nonce_counter, ncsize);
        }

        /*
        CT := ENC(IV, KEY) ^ PT;
        IV++;
        */
        zmerror ctr_enc (struct ctr_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            int32_t blocksize = ctx->cipher_block_size();
            if (ilen == 0 || blocksize <= 0){
                return ZMCRYPTO_ERR_INVALID_DSIZE;
            }

            uint8_t c;
            uint32_t n = ctx->nc_offset;

            while (ilen--)
            {
                if (n == 0) 
                {
                    ctx->cipher_enc_block (ctx->cipher_ctx, ctx->nonce_counter, ctx->temp); 

                    /*IV++*/
                    for(uint32_t i = blocksize; i > 0; i--)
                    {
                        if(++(ctx->nonce_counter[i - 1]) != 0) { break; }
                    }
                }

                c = *input++;
                *output = c ^ ctx->temp[n];        
                output++;
                n = (n + 1) % blocksize;
            }
            ctx->nc_offset = n;
            return ZMCRYPTO_ERR_SUCCESSED;
        }

        /*
        PT := ENC(IV, KEY) ^ CT;
        IV++;
        */
        zmerror ctr_dec (struct ctr_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
        {
            return ctr_enc (ctx, input, ilen, output);
        }
#endif /* ZMCRYPTO_ALGO_CTR */
