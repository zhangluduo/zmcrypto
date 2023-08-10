
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

#if !defined ZMCRYPTO_CTR_H
#define ZMCRYPTO_CTR_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_CTR

        #if !defined MAX_IV_SIZE
            #define MAX_IV_SIZE (256)
        #endif

        struct ctr_ctx
        {
            void*   (*cipher_new)            (void);
            void    (*cipher_free)           (void* ctx);
            void    (*cipher_init)           (void* ctx);
            int32_t (*cipher_block_size)     (void);
            int32_t (*cipher_ksize_min)      (void);
            int32_t (*cipher_ksize_max)      (void);
            int32_t (*cipher_ksize_multiple) (void);
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);

            void* cipher_ctx;
            uint32_t nc_offset; /* offset of nonce counter */
            uint8_t nonce_counter[MAX_IV_SIZE];
            uint8_t temp[MAX_IV_SIZE];
        } ;

        void ctr_init (
            struct ctr_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* ctx),
            int32_t (*cipher_block_size)     (void),
            int32_t (*cipher_ksize_min)      (void),
            int32_t (*cipher_ksize_max)      (void),
            int32_t (*cipher_ksize_multiple) (void),
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        );
        
        struct ctr_ctx* ctr_new (
            void
        );

        void ctr_free (
            struct ctr_ctx* ctx
        );

        zmerror ctr_set_ekey (
            struct ctr_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize, 
            uint8_t* nonce_counter, 
            uint32_t ncsize
        );

        zmerror ctr_set_dkey (
            struct ctr_ctx* ctx, 
            uint8_t* key, 
            uint32_t ksize, 
            uint8_t* nonce_counter, 
            uint32_t ncsize
        );

        zmerror ctr_enc (
            struct ctr_ctx* ctx, 
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

        zmerror ctr_dec (
            struct ctr_ctx* ctx, 
            uint8_t* input, 
            uint32_t ilen, 
            uint8_t* output
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CTR_H */
