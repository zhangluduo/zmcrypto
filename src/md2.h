
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

#if !defined ZMCRYPTO_MD2_H
#define ZMCRYPTO_MD2_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_MD2
        struct md2_ctx;

        struct md2_ctx* md2_new (
            void
        );

        void md2_free (
            struct md2_ctx* ctx
        );

        int32_t md2_digest_size (
            void
        );

        int32_t md2_block_size (
            void
        );

        void md2_init (
            struct md2_ctx* ctx
        );

        void md2_starts (
            struct md2_ctx* ctx
        );

        void md2_update (
            struct md2_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void md2_final (
            struct md2_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_MD2_H */


