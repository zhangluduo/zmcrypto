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

#if !defined ZMCRYPTO_AES_H
#define ZMCRYPTO_AES_H

#include "../src/zmconfig.h"
#include "../src/zmcrypto.h"

#ifdef  __cplusplus
extern "C" {
#endif

        struct aes_ctx;

        API struct aes_ctx* hook_aes_new(void);
        API void hook_aes_free(struct aes_ctx* ctx);
        API void hook_aes_init(struct aes_ctx* ctx);
        API int32_t hook_aes_block_size(void);
        API int32_t hook_aes_ksize_min(void);
        API int32_t hook_aes_ksize_max(void);
        API int32_t hook_aes_ksize_multiple(void);
        API zmerror hook_aes_set_ekey(struct aes_ctx* ctx, uint8_t* key, uint32_t ksize);
        API zmerror hook_aes_set_dkey(struct aes_ctx* ctx, uint8_t* key, uint32_t ksize);
        API void hook_aes_enc_block(struct aes_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext);
        API void hook_aes_dec_block(struct aes_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext);

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_AES_H */
