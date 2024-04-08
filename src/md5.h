
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

#if !defined ZMCRYPTO_MD5_H
#define ZMCRYPTO_MD5_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_MD5
        struct md5_ctx;

        struct md5_ctx* md5_new (
            void
        );

        void md5_free (
            struct md5_ctx* ctx
        );

        int32_t md5_digest_size (
            void
        );

        int32_t md5_block_size (
            void
        );

        void md5_init (
            struct md5_ctx* ctx
        );

        void md5_starts (
            struct md5_ctx* ctx
        );

        void md5_update (
            struct md5_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void md5_final (
            struct md5_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_MD5_H */


