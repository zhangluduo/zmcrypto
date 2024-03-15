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

#if !defined ZMCRYPTO_HMAC_H
#define ZMCRYPTO_HMAC_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_HMAC

        struct hmac_ctx;

        struct hmac_ctx* hmac_new (
            void
        );

        void hmac_free (
            struct hmac_ctx* ctx
        );

        void hmac_init (
            struct hmac_ctx* ctx,
            void*   (*hash_new)         (void),
            void    (*hash_free)        (void* ctx),
            int32_t (*hash_digest_size) (void),
            int32_t (*hash_block_size)  (void),
            void    (*hash_init)        (void* ctx),
            void    (*hash_starts)      (void* ctx),
            void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),
            void    (*hash_final)       (void* ctx, uint8_t* output)
        );

        zmerror hmac_starts (
            struct hmac_ctx* ctx, 
            uint8_t* key, 
            uint32_t klen
        );

        void hmac_update (
            struct hmac_ctx* ctx, 
            uint8_t* data, 
            uint32_t dlen
        );

        void hmac_final (
            struct hmac_ctx* ctx, 
            uint8_t* output
        );

        int32_t hmac_digest_size (
            struct hmac_ctx* ctx
        ); 

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_HMAC_H */
