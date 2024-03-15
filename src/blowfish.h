
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

#if !defined ZMCRYPTO_BLOWFISH_H
#define ZMCRYPTO_BLOWFISH_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_BLOWFISH

        struct blowfish_ctx;
        
        struct blowfish_ctx* blowfish_new (
            void
        );

        void blowfish_free (
            struct blowfish_ctx* ctx
        );

        void blowfish_init (
            struct blowfish_ctx* ctx
        );

        int32_t blowfish_block_size (
            void
        );

        int32_t blowfish_ksize_min (
            void
        );

        int32_t blowfish_ksize_max (
            void
        );

        int32_t blowfish_ksize_multiple (
            void
        );

        zmerror blowfish_set_ekey (
            struct blowfish_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror blowfish_set_dkey (
            struct blowfish_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void blowfish_enc_block (
            struct blowfish_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void blowfish_dec_block (
            struct blowfish_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

    #endif /* ZMCRYPTO_ALGO_BLOWFISH */

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_BLOWFISH_H */