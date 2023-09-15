
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

        typedef struct
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

            void*    cipher_ctx;
            uint64_t dlen;                 /* length that will be enc / dec */
            uint64_t aadlen;               /* length of the aad */
            uint32_t L;                    /* L value */
            uint32_t noncelen;             /* length of the nonce */
            uint32_t taglen;               /* length of the tag */

            uint64_t current_aadlen;       /* length of the currently provided aad */
            uint64_t current_datalen;      /* length of the currently provided data */

            uint32_t direction;            /* 0=encrypt, 1=decrypt */

            #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
                uint8_t b[16]; /* B_0, B_1 ... B_n */
            #endif

            uint8_t bx[16];                /* B_n ^ X_n */
            uint8_t x[16];                 /* X_0, X_1 ... X_n */
            uint8_t a[16];                 /* A_0, A_1 ... A_n, this is a counter*/
            uint8_t s[16];                 /* S_0, S_1 ... S_n */
            uint32_t b_len;                /* used length of b[16] */
        } ccm_ctx;

        ccm_ctx* ccm_new (
            void
        );

        void ccm_free (
            ccm_ctx* ctx
        );

        void ccm_init (
            ccm_ctx* ctx,
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
            ccm_ctx* ctx, 
            uint8_t *key, uint32_t klen,              /* the key of block cipher */
            uint8_t *nonce, uint32_t noncelen,        /* N-Once of counter, and it length, nust between 7 and 13 in rfc3610 */
            uint64_t datalen,                         /* 0 <= l(m) < 2^(8L) */
            uint64_t aadlen,                          /* the length of additional authenticated data, 0 <= l(a) < 2^64 */
            uint32_t taglen,                          /* Valid values are 4, 6, 8, 10, 12, 14, and 16 */
            uint32_t direction                        /* 0=encrypt or 1=decrypt */
        );

        zmerror ccm_update_aad (
            ccm_ctx *ctx, 
            uint8_t *aad,  
            uint32_t alen                             /* Updating data at one time, up to 4 bytes, 
                                                         and a total data length of up to 8 bytes */
        );

        zmerror ccm_update_data (
            ccm_ctx *ctx, 
            uint8_t *data, 
            uint32_t dlen,                            /* Updating data at one time, up to 4 bytes, 
                                                         and a total data length of up to 8 bytes */
            uint8_t *output
        );

        zmerror ccm_final (
            ccm_ctx *ctx, 
            uint8_t *tag                              /* tag buffer length same as parameter 
                                                         'taglen' in 'ccm_starts' function */
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CCM_H */
