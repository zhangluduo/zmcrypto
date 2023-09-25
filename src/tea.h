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

#if !defined ZMCRYPTO_TEA_H
#define ZMCRYPTO_TEA_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_TEA
        struct tea_ctx
        {
            int x;
        } ;

        struct tea_ctx* tea_new (
            void
        );

        void tea_free (
            struct tea_ctx* ctx
        );

        void tea_init (
            struct tea_ctx* ctx
        );

        int32_t tea_block_size(
            void
        );

        int32_t tea_ksize_min(
            void
        );

        int32_t tea_ksize_max(
            void
        );

        int32_t tea_ksize_multiple(
            void
        );

        zmerror tea_set_ekey(
            struct tea_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror tea_set_dkey(
            struct tea_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void tea_enc_block(
            struct tea_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void tea_dec_block(
            struct tea_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_TEA_H */
