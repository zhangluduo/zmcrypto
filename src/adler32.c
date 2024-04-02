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

/**
 * Some codes is from the zlib-0.71 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

#include "adler32.h"

#if defined ZMCRYPTO_ALGO_ADLER32

    struct adler32_ctx
    {
        uint32_t checksum;
    } ;

    /* slowly
    // const uint32_t MOD_ADLER = 65521;
    // uint32_t adler32(unsigned char *data, size_t len)
    // {
    //     uint32_t a = 1, b = 0;
    //     size_t index;
    //     // Process each byte of the data in order
    //     for (index = 0; index < len; ++index)
    //     {
    //     a = (a + data[index]) % MOD_ADLER;
    //     b = (b + a) % MOD_ADLER;
    //     }
    //     return (b << 16) | a;
    // }
    */

    #define BASE 65521 /* largest prime smaller than 65536 */
    #define NMAX 5552
    /* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */

    #define DO1(buf)  {s1 += *buf++; s2 += s1;}
    #define DO2(buf)  DO1(buf); DO1(buf);
    #define DO4(buf)  DO2(buf); DO2(buf);
    #define DO8(buf)  DO4(buf); DO4(buf);
    #define DO16(buf) DO8(buf); DO8(buf);

    struct adler32_ctx* adler32_new (void)
    {
        struct adler32_ctx* ctx = (struct adler32_ctx*)zmcrypto_malloc(sizeof(struct adler32_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct adler32_ctx));
        return ctx;
    }

    void adler32_free (struct adler32_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t adler32_checksum_size (void) 
    {
        return 4; 
    }

    void adler32_init (struct adler32_ctx* ctx) 
    { 
        (void)ctx; 
    }

    void adler32_starts (struct adler32_ctx* ctx) 
    {
        ctx->checksum = 1;
    }

    void adler32_update (struct adler32_ctx* ctx, uint8_t* data, uint32_t dlen) 
    {
        uint32_t s1 = ctx->checksum & 0xffff;
        uint32_t s2 = (ctx->checksum >> 16) & 0xffff;
        int32_t k = 0;

		if (!data || dlen == 0) { return; }

        while (dlen > 0) 
        {
            k = dlen < NMAX ? dlen : NMAX;
            dlen -= k;
            while (k >= 16) 
            {
                DO16(data);
                k -= 16;
            }
            if (k != 0) do 
            {
                DO1(data);
            } while (--k);
            s1 %= BASE;
            s2 %= BASE;
        }
        ctx->checksum = (s2 << 16) | s1;
    }

    void adler32_final (struct adler32_ctx* ctx, uint8_t* output) 
    {
        #if defined ENDIAN_LITTLE
            *(output + 0) = *(((uint8_t*)(&(ctx->checksum))) + 3);
            *(output + 1) = *(((uint8_t*)(&(ctx->checksum))) + 2);
            *(output + 2) = *(((uint8_t*)(&(ctx->checksum))) + 1);
            *(output + 3) = *(((uint8_t*)(&(ctx->checksum))) + 0);
        #else
            *(output + 0) = *(((uint8_t*)(&(ctx->checksum))) + 0);
            *(output + 1) = *(((uint8_t*)(&(ctx->checksum))) + 1);
            *(output + 2) = *(((uint8_t*)(&(ctx->checksum))) + 2);
            *(output + 3) = *(((uint8_t*)(&(ctx->checksum))) + 3);
        #endif
    }
#endif /* ZMCRYPTO_ALGO_ADLER32 */
