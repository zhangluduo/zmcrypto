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
 *   Date: Sep 2003
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/**
 * Some codes is from the PolarSSL 1.3.9 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

#include "sm3.h"

#if defined ZMCRYPTO_ALGO_SM3

    struct sm3_ctx* sm3_new (void)
    {
        struct sm3_ctx* ctx = (struct sm3_ctx*)zmcrypto_malloc(sizeof(struct sm3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sm3_ctx));
        return ctx;
    }

    void sm3_free (struct sm3_ctx* ctx)
    {
        zmcrypto_free(ctx);
        ctx = NULL;
    }

    int32_t sm3_digest_size (void)
    {
        return 32;
    }

    int32_t sm3_block_size (void)
    {
        return 64;
    }

    void sm3_init (struct sm3_ctx* ctx)
    {
    }

    void sm3_starts (struct sm3_ctx* ctx)
    {
    }

    void sm3_update (struct sm3_ctx* ctx, uint8_t* data, uint32_t dlen)
    {
    }

    void sm3_final (struct sm3_ctx* ctx, uint8_t* output)
    {
    }

#endif /* ZMCRYPTO_ALGO_SM3 */
