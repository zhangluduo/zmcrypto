
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

#if !defined ZMCRYPTO_OFB_H
#define ZMCRYPTO_OFB_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_OFB

        #if !defined MAX_IV_SIZE
            #define MAX_IV_SIZE (256)
        #endif

        struct ofb_ctx
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
            uint32_t iv_offset;
            uint8_t iv[MAX_IV_SIZE];
            uint8_t temp[MAX_IV_SIZE];
        } ;

        void ofb_init (
            struct ofb_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* ctx),
            int32_t (*cipher_block_size)     (void),
            int32_t (*cipher_ksize_min)      (void),
            int32_t (*cipher_ksize_max)      (void),
            int32_t (*cipher_ksize_multiple) (void),
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        );

        struct ofb_ctx* ofb_new (
            void
        );

        void ofb_free (
            struct ofb_ctx* ctx
        );

        zmerror ofb_set_ekey (
            struct ofb_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize, 
            uint8_t* iv, 
            uint32_t ivsize
        );

        zmerror ofb_set_dkey (
            struct ofb_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize, 
            uint8_t* iv, 
            uint32_t ivsize
        );

        zmerror ofb_enc (
            struct ofb_ctx* ctx, 
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

        zmerror ofb_dec (
            struct ofb_ctx* ctx, 
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_OFB_H */
