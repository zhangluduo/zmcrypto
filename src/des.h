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

#if !defined ZMCRYPTO_DES_H
#define ZMCRYPTO_DES_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_DES
        struct des_ctx;

        struct des_ctx* des_new (
            void
        );

        void des_free (
            struct des_ctx* ctx
        );

        void des_init (
            struct des_ctx* ctx
        );

        int32_t des_block_size(
            void
        );

        int32_t des_ksize_min(
            void
        );

        int32_t des_ksize_max(
            void
        );

        int32_t des_ksize_multiple(
            void
        );

        zmerror des_set_ekey(
            struct des_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror des_set_dkey(
            struct des_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void des_enc_block(
            struct des_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void des_dec_block(
            struct des_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_DES_H */
