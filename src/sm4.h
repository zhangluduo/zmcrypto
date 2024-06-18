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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_SM4_H
#define ZMCRYPTO_SM4_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_SM4
        struct sm4_ctx;

        struct sm4_ctx* sm4_new (
            void
        );

        void sm4_free (
            struct sm4_ctx* ctx
        );

        void sm4_init (
            struct sm4_ctx* ctx
        );

        int32_t sm4_block_size (
            void
        );

        int32_t sm4_ksize_min (
            void
        );

        int32_t sm4_ksize_max (
            void
        );

        int32_t sm4_ksize_multiple (
            void
        );

        zmerror sm4_set_ekey (
            struct sm4_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror sm4_set_dkey (
            struct sm4_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void sm4_enc_block (
            struct sm4_ctx* ctx, 
            uint8_t plaintext[16], 
            uint8_t ciphertext[16]
        );

        void sm4_dec_block (
            struct sm4_ctx* ctx, 
            uint8_t ciphertext[16], 
            uint8_t plaintext[16]
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_SM4_H */
