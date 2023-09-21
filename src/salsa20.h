
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

#if !defined ZMCRYPTO_SALSA20_H
#define ZMCRYPTO_SALSA20_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_SALSA20
        struct salsa20_ctx
        {
int n;
        } ;

        int32_t salsa20_ksize_min (
            void
        );

        int32_t salsa20_ksize_max (
            void
        );

        int32_t salsa20_ksize_multiple (
            void
        );

        struct salsa20_ctx* salsa20_new (
            void
        );

        void salsa20_free (
            struct salsa20_ctx* ctx
        );

        void salsa20_init (
            struct salsa20_ctx* ctx
        );

        zmerror salsa20_set_ekey(
            struct salsa20_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        zmerror salsa20_set_dkey(
            struct salsa20_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        void salsa20_set_iv(
            struct salsa20_ctx* ctx, 
            uint8_t* iv
        );

        void salsa20_encrypt(
            struct salsa20_ctx* ctx,
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

        void salsa20_decrypt(
            struct salsa20_ctx* ctx,
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_SALSA20_H */

