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

#include "ccm.h"

#if defined ZMCRYPTO_ALGO_CCM

    ccm_ctx* ccm_new (void)
    {
        return zmcrypto_malloc(sizeof(ccm_ctx));
    }

    void ccm_free (ccm_ctx* ctx)
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

    void ccm_init (ccm_ctx* ctx,
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
        zmcrypto_memset(ctx, 0, sizeof(ccm_ctx));
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
        ccm_ctx* ctx, 
        uint8_t *key, uint32_t klen,              /* the key of block cipher */
        uint8_t *nonce, uint32_t noncelen,        /* N-Once of counter, and it length */
        uint64_t datalen,                         /* 0 <= l(m) < 2^(8L) */
        uint32_t taglen,                          /* Valid values are 4, 6, 8, 10, 12, 14, and 16 */
        uint64_t aadlen,                          /* the length of additional authenticated data, 0 <= l(a) < 2^64 */
        uint32_t direction                        /* 0=encrypt or 1=decrypt */
    )
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror ccm_update_aad (ccm_ctx *ctx, uint8_t *aad, uint32_t alen)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror ccm_update_data (ccm_ctx *ctx, uint8_t *data, uint32_t dlen, uint8_t *output)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror ccm_final (ccm_ctx *ctx, uint8_t *tag)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_ALGO_CCM */
