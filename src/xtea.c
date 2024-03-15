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

#include "xtea.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_XTEA
        struct xtea_ctx
        {
            int x;
        } ;
        
        struct xtea_ctx* xtea_new (void) { return NULL; };
        void xtea_free (struct xtea_ctx* ctx) {}
        void xtea_init (struct xtea_ctx* ctx) {}
        int32_t xtea_block_size(void) { return 0; }
        int32_t xtea_ksize_min(void) { return 0; }
        int32_t xtea_ksize_max(void) { return 0; }
        int32_t xtea_ksize_multiple(void) { return 0; }
        zmerror xtea_set_ekey(struct xtea_ctx* ctx, uint8_t* key, uint32_t ksize) { return 0; }
        zmerror xtea_set_dkey(struct xtea_ctx* ctx, uint8_t* key, uint32_t ksize) { return 0; }
        void xtea_enc_block(struct xtea_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext) {}
        void xtea_dec_block(struct xtea_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext) {}

    #endif

#ifdef  __cplusplus
}
#endif
