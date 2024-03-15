
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

#if !defined ZMCRYPTO_TWOFISH_H
#define ZMCRYPTO_TWOFISH_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_TWOFISH

        struct twofish_ctx;

        struct twofish_ctx* twofish_new (
            void
        );

        void twofish_free (
            struct twofish_ctx* ctx
        );

        void twofish_init (
            struct twofish_ctx* ctx
        );

        int32_t twofish_block_size (
            void
        );

        int32_t twofish_ksize_min (
            void
        );

        int32_t twofish_ksize_max (
            void
        );

        int32_t twofish_ksize_multiple (
            void
        );

        zmerror twofish_set_ekey (
            struct twofish_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror twofish_set_dkey (
            struct twofish_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void twofish_enc_block (
            struct twofish_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        void twofish_dec_block (
            struct twofish_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

    #endif /* ZMCRYPTO_ALGO_TWOFISH */

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_TWOFISH_H */