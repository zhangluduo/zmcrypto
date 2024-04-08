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

#if !defined ZMCRYPTO_ADLER32_H
#define ZMCRYPTO_ADLER32_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_ADLER32
        struct adler32_ctx;

        struct adler32_ctx* adler32_new (
            void
        );

        void adler32_free (
            struct adler32_ctx* ctx
        );

        int32_t adler32_checksum_size (
            void
        );

        void adler32_init (
            struct adler32_ctx* ctx
        );

        void adler32_starts (
            struct adler32_ctx* ctx);

        void adler32_update (
            struct adler32_ctx* ctx, uint8_t* data, uint32_t dsize
        );

        void adler32_final (
            struct adler32_ctx* ctx, uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_ADLER32_H */
