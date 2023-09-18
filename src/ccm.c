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
 *   Date: Sep 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/*
 * Definition of CCM:
 * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
 * RFC 3610 "Counter with CBC-MAC (CCM)"
 *
 * Related:
 * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
 *
 * Definition of CCM*:
 * IEEE 802.15.4 - IEEE Standard for Local and metropolitan area networks
 * Integer representation is fixed most-significant-octet-first order and
 * the representation of octets is most-significant-bit-first order. This is
 * consistent with RFC 3610.
 */

/*
 * For learning of this algorithm, some debug message is output in the code.
 * see zmconfig.h => '#define ZMCRYPTO_DEBUG 0'
 * Zhang Luduo, 2023-09-07
 */

#include "ccm.h"
#include "debug.h"

/*                                                      
//	X_1 := E( K, B_0 )                                  
//	X_i+1 := E( K, X_i XOR B_i )  for i=1, ..., n       
//	T := first-M-bytes( X_n+1 )                         
//                                                      
//        B_0       B_1       B_2               B_n     
//         |         |         |                 |      
//         |         V         V                 V      
//         |    +-->XOR   +-->XOR           +-->XOR     
//         |    |    |    |    |            |    |      
//         V    |    V    |    V            |    V      
//       +----+ | +----+  | +----+          | +----+    
//   K-->|E() | | |E() |  | |E() |   ...    | |E() |    
//       +----+ | +----+  | +----+          | +----+    
//         |    |    |    |    |            |    |      
//         +----+    +----+    +-->     -->-+    |      
//         |         |         |         X_n     |      
//         V         V         V                 V      
//        X_1       X_2       X_3               X_n+1   

//	S_i := E( K, A_i )   for i=0, 1, 2, ...             
//                                                      
//        A_0       A_1        A_2        A_n           
//         |         |          |          |            
//         V         V          V          V            
//       +----+   +----+     +----+     +----+          
//   K-->|E() |   |E() |     |E() | ... |E() |          
//       +----+   +----+     +----+     +----+          
//         |         |          |          |            
//         |         |S_1       |S_2       |S_n         
//         |         |          |          |            
//         |         V          V          V            
//         |  M_1-->XOR  M_2-->XOR  M_n-->XOR           
//         |         |          |          |            
//         V         V          V          V            
//        S_0       C_1        C_2        C_n           
                                                        
//	U := T XOR first-M-bytes( S_0 )                     
*/                                                      

#if defined ZMCRYPTO_ALGO_CCM

    /*private BEGIN: internal interface */

    /* increment the ctr */
    #define CCM_DO_UPATE_CTR                              \
        do                                                \
        {                                                 \
            for(uint32_t i = 15; i > 1; i--)              \
            {                                             \
                if(++(ctx->a[i]) != 0) { break; }         \
            }                                             \
        } while (0);

    /* 
        encode l(a): 
        If 0 < l(a) < (2^16 - 2^8), then the length field is encoded as two
        octets which contain the value l(a) in most-significant-byte first
        order.

        If (2^16 - 2^8) <= l(a) < 2^32, then the length field is encoded as
        six octets consisting of the octets 0xff, 0xfe, and four octets
        encoding l(a) in most-significant-byte-first order.

        If 2^32 <= l(a) < 2^64, then the length field is encoded as ten
        octets consisting of the octets 0xff, 0xff, and eight octets encoding
        l(a) in most-significant-byte-first order.
    */
    /*
    returns the encoded data size, and fill encoded data into output
    */
    uint32_t ccm_encode_l_a(struct ccm_ctx* ctx, uint8_t output[10] /* max */ ){
        if (ctx->aadlen < ((1UL << 16) - (1UL << 8)))
        {
            output[0] = (ctx->aadlen >> 8) & 0xff;
            output[1] = (ctx->aadlen     ) &  0xff;
            ZMCRYPTO_OUTPUT("encoded l(a): ", output, 2);
            return 2U;
        }
        else if (ctx->aadlen < (uint64_t)1 << 32)
        {
            output[0] = 0xff;
            output[1] = 0xfe;
            output[2] = (ctx->aadlen >> 24) & 0xff;
            output[3] = (ctx->aadlen >> 16) & 0xff;
            output[4] = (ctx->aadlen >> 8 ) & 0xff;
            output[5] = (ctx->aadlen      ) & 0xff;
            ZMCRYPTO_OUTPUT("encoded l(a): ", output, 6);
            return 6U;
        }
        else
        {
            output[0] = 0xff;
            output[1] = 0xff;
            output[2] = (ctx->aadlen >> 56) & 0xff;
            output[3] = (ctx->aadlen >> 48) & 0xff;
            output[4] = (ctx->aadlen >> 40) & 0xff;
            output[5] = (ctx->aadlen >> 32) & 0xff;
            output[6] = (ctx->aadlen >> 24) & 0xff;
            output[7] = (ctx->aadlen >> 16) & 0xff;
            output[8] = (ctx->aadlen >> 8 ) & 0xff;
            output[9] = (ctx->aadlen      ) & 0xff;
            ZMCRYPTO_OUTPUT("encoded l(a): ", output, 10);
            return 10U;
        }
    }

    /* NOTE: The noncelen must be valid value*/
    void ccm_encode_B_0(struct ccm_ctx* ctx, uint8_t* nonce, uint32_t noncelen, uint8_t b_0[16])
    {
        /*
        B_0 := flags | Nonce N | l(m)

        The first block B_0 is formatted as follows, where l(m) is encoded in
        most-significant-byte first order:

            Octet Number   Contents
            ------------   ---------
            0              Flags
            1 ... 15-L     Nonce N
            16-L ... 15    l(m)

        Within the first block B_0, the Flags field is formatted as follows:

            Bit Number   Contents
            ----------   ----------------------
            7            Reserved (always zero)
            6            Adata
            5 ... 3      M'
            2 ... 0      L'

        Another way say the same thing is:  Flags = 64*Adata + 8*M' + L'.
        */

       uint32_t x = 0;

       /* store b_0 flags */
       b_0[x++] = (uint8_t)(
                ((ctx->aadlen > 0) ? (1 << 6) : 0) | /* Adata */
                ((ctx->taglen - 2) >> 1) << 3 |      /* M' */
                (ctx->L - 1)                         /* L' is size of l(m), the value is limited between 2-8 bytes*/
                );

        /* store Nonce N */
        for (uint32_t i = 0; i < 15 - ctx->L; i++) 
        {
            b_0[x++] = nonce[i];
        }

        /* store l(m) */
        for (uint32_t i = 16 - ctx->L; i < 16; i++)
        {
            b_0[x++] = (uint8_t)(ctx->dlen >> ((16 - 1 - i) * 8));
        }
    }

    /*private END */

    struct ccm_ctx* ccm_new (void)
    {
        return zmcrypto_malloc(sizeof(struct ccm_ctx));
    }

    void ccm_free (struct ccm_ctx* ctx)
    {
        if (ctx)
        {
            if (ctx->cipher_ctx)
            {
                ctx->cipher_free(ctx->cipher_ctx);
                ctx->cipher_ctx = NULL;
            }

            zmcrypto_free(ctx);
            ctx = NULL;
        }
    }

    void ccm_init (struct ccm_ctx* ctx,
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
        zmcrypto_memset(ctx, 0, sizeof(struct ccm_ctx));
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

    zmerror ccm_starts (
        struct ccm_ctx* ctx, 
        uint8_t *key, uint32_t klen,              /* the key of block cipher */
        uint8_t *nonce, uint32_t noncelen,        /* N-Once of counter, and it length */
        uint64_t datalen,                         /* 0 <= l(m) < 2^(8L) */
        uint64_t aadlen,                          /* the length of additional authenticated data, 0 <= l(a) < 2^64 */
        uint32_t taglen,                          /* Valid values are 4, 6, 8, 10, 12, 14, and 16 */
        uint32_t direction                        /* 0=encrypt or 1=decrypt */
    )
    {
        ZMCRYPTO_LOG("");
        int32_t ret;

        if (taglen < 4 || taglen > 16 || taglen % 2 != 0)
        {
            return ZMCRYPTO_ERR_INVALID_TSIZE;
        }

        /* let's get the L value. What's the L value? It's Number of octets in data length field */
        ctx->L = 0;
        ctx->dlen = datalen;
        while (datalen)
        {
            ctx->L++;
            datalen >>= 8;
        }

        /* parameter L can take on the values from 2 to 8 (recall, the value L=1 is reserved) */
        if (ctx->L <= 1) { ctx->L = 2; } 

        if (ctx->L + noncelen != 15)
        {
            ZMCRYPTO_LOG("");
            return ZMCRYPTO_ERR_INVALID_IVSIZE;
        }

        ctx->taglen    = taglen;
        ctx->noncelen  = noncelen;
        ctx->aadlen    = aadlen;
        ctx->direction = direction;

        /* rfc3610: CCM is defined for use with 128-bit block ciphers */
        if (ctx->cipher_block_size() != 16)
        {
            /* block size of underlying block cipher is not 16 */
            ZMCRYPTO_LOG("");
            return ZMCRYPTO_ERR_INVALID_BSIZE;
        }

        if (ctx->cipher_ctx)
        {
            ctx->cipher_free(ctx->cipher_ctx);
            ctx->cipher_ctx = ctx->cipher_new();
            ctx->cipher_init(ctx->cipher_ctx);
        }
        else
        {
            ctx->cipher_ctx = ctx->cipher_new();
            ctx->cipher_init(ctx->cipher_ctx);
        }

        ret = ctx->cipher_set_ekey(ctx->cipher_ctx, key, klen);
        if (ZMCRYPTO_IS_ERROR(ret))
        {
            ZMCRYPTO_LOG("");
            return ret;
        }

        ccm_encode_B_0(ctx, nonce, noncelen, ctx->bx);
        ZMCRYPTO_OUTPUT("B_0: ", ctx->bx, 16);

        /* setup ctr */

        uint32_t a_len = 0;
        ctx->a[a_len++] = ctx->L - 1;
        for (uint32_t i = 0; i < noncelen; i++) 
            { ctx->a[a_len++] = nonce[i]; }
        for (uint32_t i = noncelen + 1/*flag*/; i < 16; i++) 
            { ctx->a[a_len++] = 0; }
        ZMCRYPTO_OUTPUT("A_0: ", ctx->a, 16);

        ctx->cipher_enc_block(ctx->cipher_ctx, ctx->a, ctx->s); 
        ZMCRYPTO_OUTPUT("S_0: ", ctx->s, 16);

        ZMCRYPTO_LOG("");
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /* 
    X_1 := E( K, B_0 )
    X_i+1 := E( K, X_i XOR B_i )  for i=1, ..., n 
    */
    zmerror ccm_update_aad (struct ccm_ctx *ctx, uint8_t *aad, uint32_t alen)
    { 
        ZMCRYPTO_LOG("");
        if (ctx->current_aadlen + alen > ctx->aadlen)
        {
            return ZMCRYPTO_ERR_INVALID_DATA;
        }

        if (ctx->current_aadlen == 0)
        {
            ctx->b_len = 0;
            ctx->cipher_enc_block(ctx->cipher_ctx, ctx->bx, ctx->x); 
            ZMCRYPTO_OUTPUT("X_1: ", ctx->x, 16);

            /* setup flag of B_1 */
            ctx->b_len += ccm_encode_l_a(ctx, ctx->bx);
            for (uint32_t i = 0; i < ctx->b_len; i++)
            {
                ctx->bx[i] ^= ctx->x[i];
            }

            #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                (void)ccm_encode_l_a(ctx, ctx->b);
            #endif
        }

        for (uint32_t i = 0; i < alen; i++)
        {
            ctx->bx[ctx->b_len] = ctx->x[ctx->b_len] ^ aad[i];
            #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                ctx->b[ctx->b_len] = aad[i];
            #endif
            ctx->b_len++;
            ctx->current_aadlen++;
            if (ctx->b_len == 16){
                ctx->b_len = 0;

                ctx->cipher_enc_block(ctx->cipher_ctx, ctx->bx, ctx->x); 
                #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                    ZMCRYPTO_OUTPUT("B_[n]: ", ctx->b, 16);
                    ZMCRYPTO_OUTPUT("X_[n]: ", ctx->x, 16);
                    ZMCRYPTO_OUTPUT("A_[n]: ", ctx->a, 16);
                #endif
            }
        }

        if (ctx->current_aadlen == ctx->aadlen && ctx->b_len < 16)
        {
            for (uint32_t i = ctx->b_len; i < 16; i++)
            {
                ctx->bx[ctx->b_len] = ctx->x[ctx->b_len] ^ 0;
                #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                    ctx->b[ctx->b_len] = 0;
                #endif
                ctx->b_len++;
                
                if (ctx->b_len == 16){
                    ctx->b_len = 0;
                    ctx->cipher_enc_block(ctx->cipher_ctx, ctx->bx, ctx->x);
                    #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                        ZMCRYPTO_OUTPUT("B_[n]: ", ctx->b, 16);
                        ZMCRYPTO_OUTPUT("Bx_[n]: ", ctx->bx, 16);
                        ZMCRYPTO_OUTPUT("X_[n]: ", ctx->x, 16);
                        ZMCRYPTO_OUTPUT("A_[n]: ", ctx->a, 16);
                    #endif
                }
            }
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    /*
    X_i+1 := E( K, X_i XOR B_i )  for i=1, ..., n 
    T := first-M-bytes( X_n+1 )
    */

    /*
    S_i := E( K, A_i )   for i=0, 1, 2, ...
    */
    zmerror ccm_update_data (struct ccm_ctx *ctx, uint8_t *data, uint32_t dlen, uint8_t *output)
    {
        ZMCRYPTO_LOG("");
        if (ctx->current_datalen + dlen > ctx->dlen)
        {
            return ZMCRYPTO_ERR_INVALID_DATA;
        }

        if (ctx->current_datalen == 0)
        {
            ctx->b_len = 0;

            CCM_DO_UPATE_CTR;
            ctx->cipher_enc_block(ctx->cipher_ctx, ctx->a, ctx->s); 
            ZMCRYPTO_OUTPUT("A_[n]: ", ctx->a, 16);
            ZMCRYPTO_OUTPUT("S_[n]: ", ctx->s, 16);
            ZMCRYPTO_OUTPUT("X_[n]: ", ctx->x, 16);
        }

        for (uint32_t i = 0; i < dlen; i++)
        {
            output[i] = ctx->s[ctx->b_len] ^ data[i];
            if (ctx->direction == 0) 
                { ctx->bx[ctx->b_len] = ctx->x[ctx->b_len] ^ data[i]; }
            else 
                { ctx->bx[ctx->b_len] = ctx->x[ctx->b_len] ^ output[i]; }

            #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                ctx->b[ctx->b_len] = data[i];
            #endif
            ctx->b_len++;
            ctx->current_datalen++;

            if (ctx->b_len == 16){

                CCM_DO_UPATE_CTR;
                ctx->cipher_enc_block(ctx->cipher_ctx, ctx->a, ctx->s); 
                //ZMCRYPTO_OUTPUT("A_[n]: ", ctx->a, 16);
                //ZMCRYPTO_OUTPUT("S_[n]: ", ctx->s, 16);
                //ZMCRYPTO_OUTPUT("B_[n]: ", ctx->b, 16);

                ctx->b_len = 0;
                ctx->cipher_enc_block(ctx->cipher_ctx, ctx->bx, ctx->x);
                #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                    //ZMCRYPTO_OUTPUT("BX_[n]: ", ctx->bx, 16);
                    //ZMCRYPTO_OUTPUT("X_[n]: ", ctx->x, 16);
                #endif
            }
        }

        if (ctx->current_datalen == ctx->dlen && (ctx->b_len > 0 && ctx->b_len < 16))
        {
            for (uint32_t i = ctx->b_len; i < 16; i++)
            {
                ctx->bx[ctx->b_len] = ctx->x[ctx->b_len] ^ 0;
                
                #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                    ctx->b[ctx->b_len] = 0;
                #endif
                ctx->b_len++;
                
                if (ctx->b_len == 16){
                    ctx->cipher_enc_block(ctx->cipher_ctx, ctx->bx, ctx->x);
                    ZMCRYPTO_OUTPUT("B_[n]: ", ctx->b, 16);

                    /*
                    //CCM_DO_UPATE_CTR;
                    //ctx->cipher_enc_block(ctx->cipher_ctx, ctx->a, ctx->s); 
                    //ZMCRYPTO_OUTPUT("xA_[n]: ", ctx->a, 16);
                    //ZMCRYPTO_OUTPUT("xS_[n]: ", ctx->s, 16);
                    */

                    ctx->b_len = 0;
                }
            }
        }

        if (ctx->current_datalen == ctx->dlen)
        {
            ZMCRYPTO_OUTPUT("MAC: ", ctx->x, ctx->taglen);
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror ccm_final (struct ccm_ctx *ctx, uint8_t *tag)
    {
        ZMCRYPTO_LOG("");
        uint32_t a_len = 0;
        ctx->a[a_len++] = ctx->L - 1;
        a_len += ctx->noncelen;
        for (uint32_t i = ctx->noncelen + 1/*flag*/; i < 16; i++) 
            { ctx->a[a_len++] = 0; }
        ZMCRYPTO_OUTPUT("A_0: ", ctx->a, 16);

        ctx->cipher_enc_block(ctx->cipher_ctx, ctx->a, ctx->s); 
        ZMCRYPTO_OUTPUT("S_0: ", ctx->s, 16);

        for (uint32_t i = 0; i < ctx->taglen; i++)
        {
            tag[i] = ctx->x[i] ^ ctx->s[i];
        }
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_ALGO_CCM */
