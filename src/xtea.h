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

#if !defined ZMCRYPTO_XTEA_H
#define ZMCRYPTO_XTEA_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_XTEA
        struct xtea_ctx
        {
            int x;
        } ;

        struct xtea_ctx* xtea_new (
            void
        );

        void xtea_free (
            struct xtea_ctx* ctx
        );

        void xtea_init (
            struct xtea_ctx* ctx
        );

        int32_t xtea_block_size(
            void
        );

        int32_t xtea_ksize_min(
            void
        );

        int32_t xtea_ksize_max(
            void
        );

        int32_t xtea_ksize_multiple(
            void
        );

        zmerror xtea_set_ekey(
            struct xtea_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror xtea_set_dkey(
            struct xtea_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void xtea_enc_block(
            struct xtea_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void xtea_dec_block(
            struct xtea_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_XTEA_H */
