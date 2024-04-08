
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
 *   Date: Mar. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_SHA3_H
#define ZMCRYPTO_SHA3_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_SHA3

        struct sha3_224_ctx;
        struct sha3_256_ctx;
        struct sha3_384_ctx;
        struct sha3_512_ctx;

        struct sha3_224_ctx* sha3_224_new (
            void
        );

        void sha3_224_free (
            struct sha3_224_ctx* ctx
        );

        int32_t sha3_224_digest_size (
            void
        );

        int32_t sha3_224_block_size (
            void
        );

        void sha3_224_init (
            struct sha3_224_ctx* ctx
        );

        void sha3_224_starts (
            struct sha3_224_ctx* ctx
        );

        void sha3_224_update (
            struct sha3_224_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void sha3_224_final (
            struct sha3_224_ctx* ctx, 
            uint8_t* output
        );

        struct sha3_256_ctx* sha3_256_new (
            void
        );

        void sha3_256_free (
            struct sha3_256_ctx* ctx
        );

        int32_t sha3_256_digest_size (
            void
        );

        int32_t sha3_256_block_size (
            void
        );

        void sha3_256_init (
            struct sha3_256_ctx* ctx
        );

        void sha3_256_starts (
            struct sha3_256_ctx* ctx
        );

        void sha3_256_update (
            struct sha3_256_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void sha3_256_final (
            struct sha3_256_ctx* ctx, 
            uint8_t* output
        );

        struct sha3_384_ctx* sha3_384_new (
            void
        );

        void sha3_384_free (
            struct sha3_384_ctx* ctx
        );

        int32_t sha3_384_digest_size (
            void
        );

        int32_t sha3_384_block_size (
            void
        );

        void sha3_384_init (
            struct sha3_384_ctx* ctx
        );

        void sha3_384_starts (
            struct sha3_384_ctx* ctx
        );

        void sha3_384_update (
            struct sha3_384_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void sha3_384_final (
            struct sha3_384_ctx* ctx, 
            uint8_t* output
        );

        struct sha3_512_ctx* sha3_512_new (
            void
        );

        void sha3_512_free (
            struct sha3_512_ctx* ctx
        );

        int32_t sha3_512_digest_size (
            void
        );

        int32_t sha3_512_block_size (
            void
        );

        void sha3_512_init (
            struct sha3_512_ctx* ctx
        );

        void sha3_512_starts (
            struct sha3_512_ctx* ctx
        );

        void sha3_512_update (
            struct sha3_512_ctx* ctx, 
            uint8_t* data, 
            uint32_t dsize
        );

        void sha3_512_final (
            struct sha3_512_ctx* ctx, 
            uint8_t* output
        );
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_SHA3_H */