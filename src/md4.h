
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

#if !defined ZMCRYPTO_MD4_H
#define ZMCRYPTO_MD4_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_MD4
        struct md4_ctx;

        struct md4_ctx* md4_new (
            void
        );

        void md4_free (
            struct md4_ctx* ctx
        );

        int32_t md4_digest_size (
            void
        );

        int32_t md4_block_size (
            void
        );

        void md4_init (
            struct md4_ctx* ctx
        );

        void md4_starts (
            struct md4_ctx* ctx
        );

        void md4_update (
            struct md4_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void md4_final (
            struct md4_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_MD4_H */


