
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

#if !defined ZMCRYPTO_ED2K_H
#define ZMCRYPTO_ED2K_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" { 
#endif

    #if defined ZMCRYPTO_ALGO_ED2K
        struct ed2k_ctx;

        struct ed2k_ctx* ed2k_new (
            void
        );

        void ed2k_free (
            struct ed2k_ctx* ctx
        );

        int32_t ed2k_digest_size (
            void
        );

        int32_t ed2k_block_size (
            void
        );

        void ed2k_init (
            struct ed2k_ctx* ctx
        );

        void ed2k_starts (
            struct ed2k_ctx* ctx
        );

        void ed2k_update (
            struct ed2k_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void ed2k_final (
            struct ed2k_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_ED2K_H */
