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
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/**
 * Some codes is from the PolarSSL 1.3.9 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

#include "sha2.h"

#if defined ZMCRYPTO_ALGO_SHA2

        struct sha224_ctx* sha224_new (
            void
        ){return 0;}

        void sha224_free (
            struct sha224_ctx* ctx
        ){}

        int32_t sha224_digest_size (
            void
        ){return 0;}

        int32_t sha224_block_size (
            void
        ){return 0;}

        void sha224_init (
            struct sha224_ctx* ctx
        ){}

        void sha224_starts (
            struct sha224_ctx* ctx
        ){}

        void sha224_update (
            struct sha224_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        ){}

        void sha224_final (
            struct sha224_ctx* ctx, 
            uint8_t* output
        ){}

        struct sha256_ctx* sha256_new (
            void
        ){return 0;}

        void sha256_free (
            struct sha256_ctx* ctx
        ){}

        int32_t sha256_digest_size (
            void
        ){return 0;}

        int32_t sha256_block_size (
            void
        ){return 0;}

        void sha256_init (
            struct sha256_ctx* ctx
        ){}

        void sha256_starts (
            struct sha256_ctx* ctx
        ){}

        void sha256_update (
            struct sha256_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        ){}

        void sha256_final (
            struct sha256_ctx* ctx, 
            uint8_t* output
        ){}

        struct sha384_ctx* sha384_new (
            void
        ){return 0;}

        void sha384_free (
            struct sha384_ctx* ctx
        ){}

        int32_t sha384_digest_size (
            void
        ){return 0;}

        int32_t sha384_block_size (
            void
        ){return 0;}

        void sha384_init (
            struct sha384_ctx* ctx
        ){}

        void sha384_starts (
            struct sha384_ctx* ctx
        ){}

        void sha384_update (
            struct sha384_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        ){}

        void sha384_final (
            struct sha384_ctx* ctx, 
            uint8_t* output
        ){}

        struct sha512_ctx* sha512_new (
            void
        ){return 0;}

        void sha512_free (
            struct sha512_ctx* ctx
        ){}

        int32_t sha512_digest_size (
            void
        ){return 0;}

        int32_t sha512_block_size (
            void
        ){return 0;}

        void sha512_init (
            struct sha512_ctx* ctx
        ){}

        void sha512_starts (
            struct sha512_ctx* ctx
        ){}

        void sha512_update (
            struct sha512_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        ){}

        void sha512_final (
            struct sha512_ctx* ctx, 
            uint8_t* output
        ){}

#endif /* ZMCRYPTO_ALGO_SHA2 */