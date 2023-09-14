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

#if !defined ZMCRYPTO_CMAC_H
#define ZMCRYPTO_CMAC_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_CMAC

        struct cmac_ctx
        {
            void*   (*cipher_new)            (void);
            void    (*cipher_free)           (void* ctx);
            void    (*cipher_init)           (void* ctx);
            int32_t (*cipher_block_size)     (void);
            int32_t (*cipher_ksize_min)      (void);
            int32_t (*cipher_ksize_max)      (void);
            int32_t (*cipher_ksize_multiple) (void);
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
            int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize);
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);
            void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext);

            void* cipher_ctx;
            int32_t unprocessed_len;
            uint8_t unprocessed_block[ZMCRYPTO_MAX_BLOCKSIZE];
            uint8_t state[ZMCRYPTO_MAX_BLOCKSIZE];
        } ;

        struct cmac_ctx* cmac_new (
            void
        );

        void cmac_free (
            struct cmac_ctx* ctx
        );

        void cmac_init (
            struct cmac_ctx* ctx,
            void*   (*cipher_new)            (void),
            void    (*cipher_free)           (void* ctx),
            void    (*cipher_init)           (void* ctx),
            int32_t (*cipher_block_size)     (void),
            int32_t (*cipher_ksize_min)      (void),
            int32_t (*cipher_ksize_max)      (void),
            int32_t (*cipher_ksize_multiple) (void),
            int32_t (*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
            int32_t (*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize),
            void    (*cipher_enc_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext),
            void    (*cipher_dec_block)      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext)
        );
        
        void cmac_reset (
            struct cmac_ctx* ctx
        );

        zmerror cmac_starts (
            struct cmac_ctx* ctx, uint8_t* key, uint32_t klen
        );        

        void cmac_update (
            struct cmac_ctx* ctx, uint8_t* data, uint32_t dlen
        );

        void cmac_final (
            struct cmac_ctx* ctx, uint8_t* output
        );

        int32_t cmac_digest_size (
            struct cmac_ctx* ctx
        ); 

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CMAC_H */
