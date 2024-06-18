
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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/*
 *  The Blowfish block cipher was designed by Bruce Schneier in 1993.
 *  http://www.schneier.com/blowfish.html
 *  http://en.wikipedia.org/wiki/Blowfish_%28cipher%29
 *
 */

#include "twofish.h"

#if defined ZMCRYPTO_ALGO_TWOFISH

    struct twofish_ctx
    {
        int n;
    } ;
    
    struct twofish_ctx* twofish_new (void)
    {
        struct twofish_ctx* ctx = (struct twofish_ctx*)zmcrypto_malloc(sizeof(struct twofish_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct twofish_ctx));
        return ctx;
    }

    void twofish_free (struct twofish_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    void twofish_init (struct twofish_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct twofish_ctx));
    }

    int32_t twofish_block_size (void){return 0;}

    int32_t twofish_ksize_min (void){return 16;}

    int32_t twofish_ksize_max (void){return 32;}

    int32_t twofish_ksize_multiple (void){return 8;}

    zmerror twofish_set_ekey (struct twofish_ctx* ctx, uint8_t* key, uint32_t ksize){return 0;}

    zmerror twofish_set_dkey (struct twofish_ctx* ctx, uint8_t* key, uint32_t ksize){return 0;}

    void twofish_enc_block (struct twofish_ctx* ctx, uint8_t plaintext[16], uint8_t ciphertext[16]){}

    void twofish_dec_block (struct twofish_ctx* ctx, uint8_t ciphertext[16], uint8_t plaintext[16]){}

#endif /* ZMCRYPTO_ALGO_TWOFISH */
