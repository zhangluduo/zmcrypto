
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
 *   Date: Nov. 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_SHA1_H
#define ZMCRYPTO_SHA1_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_SHA1
        struct sha1_ctx;

        struct sha1_ctx* sha1_new (
            void
        );

        void sha1_free (
            struct sha1_ctx* ctx
        );

        int32_t sha1_digest_size (
            void
        );

        int32_t sha1_block_size (
            void
        );

        void sha1_init (
            struct sha1_ctx* ctx
        );

        void sha1_starts (
            struct sha1_ctx* ctx
        );

        void sha1_update (
            struct sha1_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void sha1_final (
            struct sha1_ctx* ctx, 
            uint8_t output[20]
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_SHA1_H */


