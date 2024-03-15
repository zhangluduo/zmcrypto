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

        typedef struct
        {
            uint32_t nr;      /*!<  number of rounds  */
            uint32_t *rk;     /*!<  AES round keys    */
            uint32_t buf[68]; /*!<  unaligned data    */
        } aes_ctx;

        API aes_ctx* aes_new2 (
            void
        );

        API void aes_free2 (
            aes_ctx* ctx
        );

        API void aes_init2 (
            aes_ctx* ctx
        );

        API int32_t aes_block_size2 (
            void
        );

        API int32_t aes_ksize_min2 (
            void
        );

        API int32_t aes_ksize_max2 (
            void
        );

        API int32_t aes_ksize_multiple2 (
            void
        );

        /* valid key size are 16, 24 or 32 */
        API zmerror aes_set_ekey2 (
            aes_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        API zmerror aes_set_dkey2 (
            aes_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize
        );

        API void aes_enc_block2 (
            aes_ctx* ctx, 
            uint8_t* plaintext, 
            uint8_t* ciphertext
        );

        API void aes_dec_block2 (
            aes_ctx* ctx, 
            uint8_t* ciphertext, 
            uint8_t* plaintext
        );

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_AES_H */
