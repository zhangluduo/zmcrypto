
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

#if !defined ZMCRYPTO_RC4_H
#define ZMCRYPTO_RC4_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_RC4
        struct rc4_ctx
        {
            uint32_t x;     /*!< permutation index */
            uint32_t y;     /*!< permutation index */
            uint8_t m[256]; /*!< permutation table */
        } ;

        int32_t rc4_ksize_min (
            void
        );

        int32_t rc4_ksize_max (
            void
        );

        int32_t rc4_ksize_multiple (
            void
        );

        struct rc4_ctx* rc4_new (
            void
        );

        void rc4_free (
            struct rc4_ctx* ctx
        );

        void rc4_init (
            struct rc4_ctx* ctx
        );

        zmerror rc4_set_ekey(
            struct rc4_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror rc4_set_dkey(
            struct rc4_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void rc4_encrypt(
            struct rc4_ctx* ctx,
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

        void rc4_decrypt(
            struct rc4_ctx* ctx,
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_RC4_H */

