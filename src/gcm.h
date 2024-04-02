
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
 *   Date: Apr. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_GCM_H
#define ZMCRYPTO_GCM_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" { 
#endif

    #if defined ZMCRYPTO_ALGO_GCM

        struct gcm_ctx;

        struct gcm_ctx* gcm_new (
            void
        );

        void gcm_free (
            struct gcm_ctx* ctx
        );

        void gcm_init (
            struct gcm_ctx* ctx,
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
            void    (*cipher_dec_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        );

        zmerror gcm_starts (
            struct gcm_ctx* ctx,
            uint8_t *key, uint32_t klen,
            uint8_t *iv, uint32_t ivlen,
            uint32_t direction
        );

        zmerror gcm_update_aad (
            struct gcm_ctx* ctx,
            uint8_t *aad,  
            uint32_t alen
        );

        zmerror gcm_update_data (
            struct gcm_ctx* ctx,
            uint8_t *data, 
            uint32_t dlen, 
            uint8_t *output
        );

        /*valid taglen bwtween 4 and 16*/
        zmerror gcm_final (
            struct gcm_ctx* ctx,
            uint8_t *tag,
            uint32_t taglen
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_GCM_H */
