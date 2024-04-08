
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

#if !defined ZMCRYPTO_PBKDF2_H
#define ZMCRYPTO_PBKDF2_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_PBKDF2

    zmerror pbkdf2 (
            void*   (*hash_new)         (void),
            void    (*hash_free)        (void* ctx),
            int32_t (*hash_digest_size) (void),
            int32_t (*hash_block_size)  (void),
            void    (*hash_init)        (void* ctx),
            void    (*hash_starts)      (void* ctx),
            void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dsize),
            void    (*hash_final)       (void* ctx, uint8_t* output),
            uint8_t* p, 
            uint32_t plen, 
            uint8_t* s, 
            uint32_t slen, 
            uint32_t c, 
            uint8_t* dk, 
            uint32_t dklen
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_PBKDF2_H */

