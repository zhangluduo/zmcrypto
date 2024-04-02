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

#include "cmac.h"

#if defined ZMCRYPTO_ALGO_CMAC

    struct cmac_ctx
    {
        void*   (*cipher_new)            (void);
        void    (*cipher_free)           (void* ctx);
        void    (*cipher_init)           (void* ctx);
        int32_t (*cipher_block_size)     (void);
        int32_t (*cipher_ksize_min)      (void);
        int32_t (*cipher_ksize_max)      (void);
        int32_t (*cipher_ksize_multiple) (void);
        int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
        int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize);
        void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);
        void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext);

        void* cipher_ctx;
        int32_t unprocessed_len;
        uint8_t unprocessed_block[ZMCRYPTO_MAX_BLOCKSIZE];
        uint8_t state[ZMCRYPTO_MAX_BLOCKSIZE];
    } ;

    void cmac_xor_block (unsigned char *output, const unsigned char *input1, const unsigned char *input2, const size_t block_size)
    {
        for(size_t idx = 0; idx < block_size; idx++ )
        {
            output[ idx ] = input1[ idx ] ^ input2[ idx ];
        }
    }

    zmerror cmac_multiply_by_u( unsigned char *output, const unsigned char *input, int32_t blocksize)
    {
        unsigned char mask;
        unsigned char overflow = 0x00;
        int32_t i;

        for (i = blocksize - 1; i >= 0; i-- )
        {
            output[i] = input[i] << 1 | overflow;
            overflow = input[i] >> 7;
        }

        /* mask = ( input[0] >> 7 ) ? 0xff : 0x00
        * using bit operations to avoid branches */

        /* MSVC has a warning about unary minus on unsigned, but this is
        * well-defined and precisely what we want to do here */
        #if defined(_MSC_VER)
        #pragma warning( push )
        #pragma warning( disable : 4146 )
        #endif
            mask = - ( input[0] >> 7 );
        #if defined(_MSC_VER)
        #pragma warning( pop )
        #endif

        if (blocksize == 8)
        {
            output[7] ^= 0x1B & mask;
        }
        else if (blocksize == 16)
        {
            output[15] ^= 0x87 & mask;
        }
        else if (blocksize == 32)
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^256 + x^10 + x^5 + x^2 + 1
            output[30] ^= 0x04;
            output[31] ^= 0x25 & mask;
        }
        else if (blocksize == 64)
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^512 + x^8 + x^5 + x^2 + 1
            output[62] ^= 0x01;
            output[63] ^= 0x25 & mask;
        }
        else if (blocksize == 128)
        {
            // https://crypto.stackexchange.com/q/9815/10496
            // Polynomial x^1024 + x^19 + x^6 + x + 1
            output[125] ^= 0x08;
            output[126] ^= 0x00;
            output[127] ^= 0x43 & mask;
        }
        else
        {
            return ZMCRYPTO_ERR_INVALID_BSIZE;
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /*
    * Create padded last block from (partial) last block.
    *
    * We can't use the padding option from the cipher layer, as it only works for
    * CBC and we use ECB mode, and anyway we need to XOR K1 or K2 in addition.
    */
    void cmac_pad(uint8_t padded_block[ZMCRYPTO_MAX_BLOCKSIZE], uint32_t padded_block_len, const uint8_t *last_block, uint32_t last_block_len)
    {
        for(uint32_t j = 0; j < padded_block_len; j++)
        {
            if (j < last_block_len)
            {
                padded_block[j] = last_block[j];
            }
            else if (j == last_block_len)
            {
                padded_block[j] = 0x80;
            }
            else
            {
                padded_block[j] = 0x00;
            }
        }
    }

    /*
    * Generate subkeys
    *
    * - as specified by RFC 4493, section 2.3 Subkey Generation Algorithm
    */
    zmerror cmac_generate_subkeys(struct cmac_ctx* ctx, unsigned char* K1, unsigned char* K2 )
    {
        zmerror ret = 0;
        unsigned char L[16];
        zmcrypto_memset (L, 0, sizeof(L));

        /* Calculate Ek(0) */
        ctx->cipher_enc_block (ctx->cipher_ctx, L, L);

        /*
        * Generate K1 and K2
        */
        if ((ret = cmac_multiply_by_u (K1, L , ctx->cipher_block_size())) != ZMCRYPTO_ERR_SUCCESSED)
        { 
            goto fail; 
        }

        if ((ret = cmac_multiply_by_u (K2, K1 , ctx->cipher_block_size())) != ZMCRYPTO_ERR_SUCCESSED)
        { 
            goto fail; 
        }

        return ZMCRYPTO_ERR_SUCCESSED;

    fail:

        return ( ret );
    }

    struct cmac_ctx* cmac_new (void) 
    { 
        return zmcrypto_malloc(sizeof(struct cmac_ctx)); 
    }

    void cmac_free (struct cmac_ctx* ctx) 
    { 
        if (ctx)
        { 
            if (ctx->cipher_ctx)
            {
                ctx->cipher_free(ctx->cipher_ctx);
                ctx->cipher_ctx = NULL;
            }
            zmcrypto_free(ctx); 
        } 
    }
    void cmac_init (struct cmac_ctx* ctx,
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
        zmcrypto_memset(ctx, 0, sizeof(struct cmac_ctx));

        ctx->cipher_new            = cipher_new           ;
        ctx->cipher_free           = cipher_free          ;
        ctx->cipher_init           = cipher_init          ;
        ctx->cipher_block_size     = cipher_block_size    ;
        ctx->cipher_ksize_min      = cipher_ksize_min     ;
        ctx->cipher_ksize_max      = cipher_ksize_max     ;
        ctx->cipher_ksize_multiple = cipher_ksize_multiple;
        ctx->cipher_set_ekey       = cipher_set_ekey      ;
        ctx->cipher_set_dkey       = cipher_set_dkey      ;
        ctx->cipher_enc_block      = cipher_enc_block     ;
        ctx->cipher_dec_block      = cipher_dec_block     ;
    }

    zmerror cmac_starts (struct cmac_ctx* ctx, uint8_t* key, uint32_t klen) 
    {
        if (!(ctx->cipher_ctx))
        {
            ctx->cipher_ctx = ctx->cipher_new();
        }

        if (ctx->cipher_block_size() != 8 && ctx->cipher_block_size() != 16 && ctx->cipher_block_size() != 32 &&
            ctx->cipher_block_size() != 64 && ctx->cipher_block_size() != 128)
        {
            return ZMCRYPTO_ERR_INVALID_BSIZE;
        }

        if (ctx->cipher_set_ekey(ctx->cipher_ctx, key, klen) <= 0)
        {
            return ZMCRYPTO_ERR_CALLBACK;
        }
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    void cmac_update (struct cmac_ctx* ctx, uint8_t* data, uint32_t dlen) 
    {
        /* Is there data still to process from the last call, that's greater in
        * size than a block? */
        if (ctx->unprocessed_len > 0 && dlen > (uint32_t)(ctx->cipher_block_size() - ctx->unprocessed_len))
        {
            zmcrypto_memcpy (&(ctx->unprocessed_block[ctx->unprocessed_len]), data, ctx->cipher_block_size() - ctx->unprocessed_len);
            cmac_xor_block (ctx->state, ctx->unprocessed_block, ctx->state, ctx->cipher_block_size());
            ctx->cipher_enc_block(ctx->cipher_ctx, ctx->state, ctx->state);
            data += ctx->cipher_block_size() - ctx->unprocessed_len;
            dlen -= ctx->cipher_block_size() - ctx->unprocessed_len;
            ctx->unprocessed_len = 0;
        }

        /* n is the number of blocks including any final partial block */
        uint32_t n = (dlen + ctx->cipher_block_size() - 1) / ctx->cipher_block_size();

        /* Iterate across the input data in block sized chunks, excluding any
        * final partial or complete block */
        for(uint32_t j = 1; j < n; j++ )
        {
            cmac_xor_block (ctx->state, data, ctx->state, ctx->cipher_block_size());
            ctx->cipher_enc_block(ctx->cipher_ctx, ctx->state, ctx->state);
            dlen -= ctx->cipher_block_size();
            data += ctx->cipher_block_size();
        }

        /* If there is data left over that wasn't aligned to a block */
        if (dlen > 0)
        {
            zmcrypto_memcpy (&(ctx->unprocessed_block[ctx->unprocessed_len]), data, dlen);
            ctx->unprocessed_len += dlen;
        }
    }

    void cmac_final (struct cmac_ctx* ctx, uint8_t* output) 
    {
        unsigned char *last_block;
        unsigned char K1[ZMCRYPTO_MAX_BLOCKSIZE];
        unsigned char K2[ZMCRYPTO_MAX_BLOCKSIZE];
        unsigned char M_last[ZMCRYPTO_MAX_BLOCKSIZE];
    
        zmcrypto_memset (&K1, 0, sizeof(K1));
        zmcrypto_memset (&K2, 0, sizeof(K2));
        (void)cmac_generate_subkeys(ctx, K1, K2);

        last_block = ctx->unprocessed_block;

        /* Calculate last block */
        if (ctx->unprocessed_len < ctx->cipher_block_size())
        {
            cmac_pad (M_last, ctx->cipher_block_size(), last_block, ctx->unprocessed_len);
            cmac_xor_block (M_last, M_last, K2, ctx->cipher_block_size());
        }
        else
        {
            /* Last block is complete block */
            cmac_xor_block (M_last, last_block, K1, ctx->cipher_block_size());
        }

        cmac_xor_block (ctx->state, M_last, ctx->state, ctx->cipher_block_size());
        ctx->cipher_enc_block(ctx->cipher_ctx, ctx->state, ctx->state);
        zmcrypto_memcpy (output, ctx->state, ctx->cipher_block_size());
        ctx->unprocessed_len = 0;
    }

    int32_t cmac_digest_size (struct cmac_ctx* ctx)
    {
        if (ctx->cipher_block_size)
        {
            return ctx->cipher_block_size();
        }
        return ZMCRYPTO_ERR_NULL_PTR;
    }
#endif /* ZMCRYPTO_ALGO_CMAC */
