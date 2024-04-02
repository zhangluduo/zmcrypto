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

#include "cfb.h"

#if defined ZMCRYPTO_ALGO_CFB

    struct cfb_ctx
    {
        void*   (*cipher_new)           (void);
        void(*cipher_free)              (void* ctx);
        void(*cipher_init)              (void* ctx);
        int32_t(*cipher_block_size)     (void);
        int32_t(*cipher_ksize_min)      (void);
        int32_t(*cipher_ksize_max)      (void);
        int32_t(*cipher_ksize_multiple) (void);
        int32_t(*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
        int32_t(*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize);
        void(*cipher_enc_block)         (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);
        void(*cipher_dec_block)         (void* ctx, uint8_t* ciphertext, uint8_t* plaintext);

        void* cipher_ctx;
        uint32_t iv_offset;
        uint8_t iv[ZMCRYPTO_MAX_IVSIZE];
        uint8_t temp[ZMCRYPTO_MAX_IVSIZE];

        /*
        SP 800-38A
        6.3
        For performance considerations, the feedback size value uses the block size.
        */
        /*
        uint32_t feedback_bits;
        */
    } ;
    void cfb_init (struct cfb_ctx* ctx,
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
        ctx->iv_offset             = 0;
    }

    struct cfb_ctx* cfb_new(void)
    { 
        struct cfb_ctx* ctx = (struct cfb_ctx*)zmcrypto_malloc(sizeof(struct cfb_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct cfb_ctx));
        return ctx;
    }

    void cfb_free (struct cfb_ctx* ctx)
    {
        if (ctx->cipher_ctx){
            ctx->cipher_free(ctx->cipher_ctx);
            ctx->cipher_ctx = NULL;
        }
        zmcrypto_free (ctx);
    }

    zmerror cfb_set_ekey (struct cfb_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)
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

    zmerror cfb_set_dkey (struct cfb_ctx* ctx, uint8_t* key, uint32_t ksize, uint8_t* iv, uint32_t ivsize)
    {
        return cfb_set_ekey (ctx, key, ksize, iv, ivsize);
    }

    /*
    CT := ENC(IV, KEY) ^ PT;
    IV := CT;
    */
    zmerror cfb_enc (struct cfb_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
    {
        int32_t blocksize = ctx->cipher_block_size();
        if (ilen == 0 || blocksize <= 0){
            return ZMCRYPTO_ERR_INVALID_DSIZE;
        }

        uint8_t c;
        uint32_t n = ctx->iv_offset;

        while (ilen--)
        {
            if (n == 0) { ctx->cipher_enc_block (ctx->cipher_ctx, ctx->iv, ctx->temp); }
            c = *input++;
            *output = c ^ ctx->temp[n];    
            ctx->iv[n] = *output;            
            output++;
            n = (n + 1) % blocksize;
        }
        ctx->iv_offset = n;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /*
    PT := ENC(IV, KEY) ^ CT;
    IV := CT;
    */
    zmerror cfb_dec (struct cfb_ctx* ctx, uint8_t* input, uint32_t ilen, uint8_t* output)
    {
        int32_t blocksize = ctx->cipher_block_size();
        if (ilen == 0 || blocksize <= 0){
            return ZMCRYPTO_ERR_INVALID_DSIZE;
        }

        uint8_t c;
        uint32_t n = ctx->iv_offset;
        while (ilen--)
        {
            if (n == 0) { ctx->cipher_enc_block (ctx->cipher_ctx, ctx->iv, ctx->temp); }
            c = *input++;
            *output = c ^ ctx->temp[n];  
            ctx->iv[n] = c;              
            output++;
            n = (n + 1) % blocksize;
        }
        ctx->iv_offset = n;
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_ALGO_CFB */
