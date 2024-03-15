
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

#if !defined ZMCRYPTO_CCM_H
#define ZMCRYPTO_CCM_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_CCM

        struct ccm_ctx;

        struct ccm_ctx* ccm_new (
            void
        );

        void ccm_free (
            struct ccm_ctx* ctx
        );

        void ccm_init (
            struct ccm_ctx* ctx,
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
        );

        zmerror ccm_starts (
            struct ccm_ctx* ctx, 
            uint8_t *key, uint32_t klen,              /* the key of block cipher */
            uint8_t *nonce, uint32_t noncelen,        /* N-Once of counter, and it length, nust between 7 and 13 in rfc3610 */
            uint64_t datalen,                         /* 0 <= l(m) < 2^(8L) */
            uint64_t aadlen,                          /* the length of additional authenticated data, 0 <= l(a) < 2^64 */
            uint32_t taglen,                          /* Valid values are 4, 6, 8, 10, 12, 14, and 16 */
            uint32_t direction                        /* 0=encrypt or 1=decrypt */
        );

        zmerror ccm_update_aad (
            struct ccm_ctx *ctx, 
            uint8_t *aad,  
            uint32_t alen                             /* Updating data at one time, up to 4 bytes, 
                                                         and a total data length of up to 8 bytes */
        );

        zmerror ccm_update_data (
            struct ccm_ctx *ctx, 
            uint8_t *data, 
            uint32_t dlen,                            /* Updating data at one time, up to 4 bytes, 
                                                         and a total data length of up to 8 bytes */
            uint8_t *output
        );

        zmerror ccm_final (
            struct ccm_ctx *ctx, 
            uint8_t *tag                              /* tag buffer length same as parameter 
                                                         'taglen' in 'ccm_starts' function */
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CCM_H */
