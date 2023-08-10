
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
            uint64_t ilen,                 /* length that will be enc / dec */
                     aadlen,               /* length of the aad */
                     current_ilen,         /* current processed length */
                     current_aadlen;       /* length of the currently provided add */

            uint32_t L,                    /* L value */
                     noncelen,             /* length of the nonce */
                     taglen;               /* length of the tag (encoded in M value) */

            uint8_t pad[16],               /* flags | Nonce N | l(m) */
                    ctr[16],
                    ctr_pad[16],
                    ctr_len;

            uint32_t x;                    /* index in PAD */
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
            uint32_t taglen,                          /* Valid values are 4, 6, 8, 10, 12, 14, and 16 */
            uint64_t aadlen,                          /* the length of additional authenticated data, 0 <= l(a) < 2^64 */
            uint32_t direction                        /* 0=encrypt or 1=decrypt */
        );

        zmerror ccm_update_aad (
            ccm_ctx *ctx, 
            uint8_t *aad,  
            uint32_t alen
        );

        zmerror ccm_update_data (
            ccm_ctx *ctx, 
            uint8_t *data, 
            uint32_t dlen, 
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
