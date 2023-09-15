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

 /**
 * Reference: 
 *     [Announcing the ADVANCED ENCRYPTION STANDARD (SM4)]
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 */

#include "sm4.h"

#if defined ZMCRYPTO_ALGO_SM4

    struct sm4_ctx* sm4_new (void)
    {
        struct sm4_ctx* ctx = (struct sm4_ctx*)zmcrypto_malloc(sizeof(struct sm4_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sm4_ctx));
        return ctx;
    }

    void sm4_free (struct sm4_ctx* ctx)
    {
        zmcrypto_free(ctx);
        ctx = NULL;
    }

    void sm4_init (struct sm4_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct sm4_ctx));
    }

    int32_t sm4_block_size (void)
        { return 16; }

    int32_t sm4_ksize_min (void)
        { return 16; }

    int32_t sm4_ksize_max (void)
        { return 16; }

    int32_t sm4_ksize_multiple (void)
        { return 16; }

    int32_t sm4_set_ekey (struct sm4_ctx* ctx, uint8_t* key, uint32_t ksize)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror sm4_set_dkey (struct sm4_ctx* ctx, uint8_t* key, uint32_t ksize)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    void sm4_enc_block (struct sm4_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext)
    {
    }

    void sm4_dec_block (struct sm4_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext)
    {
    }
#endif /* ZMCRYPTO_ALGO_SM4 */
