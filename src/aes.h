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

#if !defined ZMCRYPTO_AES_H
#define ZMCRYPTO_AES_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_AES
        struct aes_ctx;

        struct aes_ctx* aes_new (
            void
        );

        void aes_free (
            struct aes_ctx* ctx
        );

        void aes_init (
            struct aes_ctx* ctx
        );

        int32_t aes_block_size (
            void
        );

        int32_t aes_ksize_min (
            void
        );

        int32_t aes_ksize_max (
            void
        );

        int32_t aes_ksize_multiple (
            void
        );

        /* valid key size are 16, 24 or 32 */
        zmerror aes_set_ekey (
            struct aes_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror aes_set_dkey (
            struct aes_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void aes_enc_block (
            struct aes_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void aes_dec_block (
            struct aes_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_AES_H */
