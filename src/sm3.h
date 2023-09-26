
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
 *   Date: Sep 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_SM3_H
#define ZMCRYPTO_SM3_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_SM3
        struct sm3_ctx
        {
            uint32_t total[2];     /*!< number of bytes processed  */
            uint32_t state[8];     /*!< intermediate digest state  */
            uint8_t buffer[64];    /*!< data block being processed */
        } ;

        struct sm3_ctx* sm3_new (
            void
        );

        void sm3_free (
            struct sm3_ctx* ctx
        );

        int32_t sm3_digest_size (
            void
        );

        int32_t sm3_block_size (
            void
        );

        void sm3_init (
            struct sm3_ctx* ctx
        );

        void sm3_starts (
            struct sm3_ctx* ctx
        );

        void sm3_update (
            struct sm3_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        );

        void sm3_final (
            struct sm3_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_SM3_H */


