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
 *   Date: Apr. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/**
 * Some codes is from the PolarSSL 1.3.9 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

/*
 *  The MD4 algorithm was designed by Ron Rivest in 1991.
 *  http://www.ietf.org/rfc/rfc1321.txt
 */

#include "md4.h"

#if defined ZMCRYPTO_ALGO_MD4

    struct md4_ctx
    {
        uint32_t total[2];          /*!< number of bytes processed  */
        uint32_t state[4];          /*!< intermediate digest state  */
        uint8_t buffer[64];         /*!< data block being processed */
    } ;

    struct md4_ctx* md4_new (void)
    {
        struct md4_ctx* ctx = (struct md4_ctx*)zmcrypto_malloc(sizeof(struct md4_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct md4_ctx));
        return ctx;
    }

    void md4_free (struct md4_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t md4_digest_size (void)
    { 
        return 16;
    }

    int32_t md4_block_size (void) 
    { 
        return 64; 
    }

    void md4_init (struct md4_ctx* ctx)
    { 
        zmcrypto_memset(ctx, 0, sizeof(struct md4_ctx)); 
    }

    void md4_process(struct md4_ctx *ctx, const uint8_t data[64] )
    {
        uint32_t X[16], A, B, C, D;

        GET_UINT32_LE( X[ 0], data,  0 );
        GET_UINT32_LE( X[ 1], data,  4 );
        GET_UINT32_LE( X[ 2], data,  8 );
        GET_UINT32_LE( X[ 3], data, 12 );
        GET_UINT32_LE( X[ 4], data, 16 );
        GET_UINT32_LE( X[ 5], data, 20 );
        GET_UINT32_LE( X[ 6], data, 24 );
        GET_UINT32_LE( X[ 7], data, 28 );
        GET_UINT32_LE( X[ 8], data, 32 );
        GET_UINT32_LE( X[ 9], data, 36 );
        GET_UINT32_LE( X[10], data, 40 );
        GET_UINT32_LE( X[11], data, 44 );
        GET_UINT32_LE( X[12], data, 48 );
        GET_UINT32_LE( X[13], data, 52 );
        GET_UINT32_LE( X[14], data, 56 );
        GET_UINT32_LE( X[15], data, 60 );

    #define S(x,n) ((x << n) | ((x & 0xFFFFFFFF) >> (32 - n)))

        A = ctx->state[0];
        B = ctx->state[1];
        C = ctx->state[2];
        D = ctx->state[3];

    #define F(x, y, z) ((x & y) | ((~x) & z))
    #define P(a,b,c,d,x,s) { a += F(b,c,d) + x; a = S(a,s); }

        P( A, B, C, D, X[ 0],  3 );
        P( D, A, B, C, X[ 1],  7 );
        P( C, D, A, B, X[ 2], 11 );
        P( B, C, D, A, X[ 3], 19 );
        P( A, B, C, D, X[ 4],  3 );
        P( D, A, B, C, X[ 5],  7 );
        P( C, D, A, B, X[ 6], 11 );
        P( B, C, D, A, X[ 7], 19 );
        P( A, B, C, D, X[ 8],  3 );
        P( D, A, B, C, X[ 9],  7 );
        P( C, D, A, B, X[10], 11 );
        P( B, C, D, A, X[11], 19 );
        P( A, B, C, D, X[12],  3 );
        P( D, A, B, C, X[13],  7 );
        P( C, D, A, B, X[14], 11 );
        P( B, C, D, A, X[15], 19 );

    #undef P
    #undef F

    #define F(x,y,z) ((x & y) | (x & z) | (y & z))
    #define P(a,b,c,d,x,s) { a += F(b,c,d) + x + 0x5A827999; a = S(a,s); }

        P( A, B, C, D, X[ 0],  3 );
        P( D, A, B, C, X[ 4],  5 );
        P( C, D, A, B, X[ 8],  9 );
        P( B, C, D, A, X[12], 13 );
        P( A, B, C, D, X[ 1],  3 );
        P( D, A, B, C, X[ 5],  5 );
        P( C, D, A, B, X[ 9],  9 );
        P( B, C, D, A, X[13], 13 );
        P( A, B, C, D, X[ 2],  3 );
        P( D, A, B, C, X[ 6],  5 );
        P( C, D, A, B, X[10],  9 );
        P( B, C, D, A, X[14], 13 );
        P( A, B, C, D, X[ 3],  3 );
        P( D, A, B, C, X[ 7],  5 );
        P( C, D, A, B, X[11],  9 );
        P( B, C, D, A, X[15], 13 );

    #undef P
    #undef F

    #define F(x,y,z) (x ^ y ^ z)
    #define P(a,b,c,d,x,s) { a += F(b,c,d) + x + 0x6ED9EBA1; a = S(a,s); }

        P( A, B, C, D, X[ 0],  3 );
        P( D, A, B, C, X[ 8],  9 );
        P( C, D, A, B, X[ 4], 11 );
        P( B, C, D, A, X[12], 15 );
        P( A, B, C, D, X[ 2],  3 );
        P( D, A, B, C, X[10],  9 );
        P( C, D, A, B, X[ 6], 11 );
        P( B, C, D, A, X[14], 15 );
        P( A, B, C, D, X[ 1],  3 );
        P( D, A, B, C, X[ 9],  9 );
        P( C, D, A, B, X[ 5], 11 );
        P( B, C, D, A, X[13], 15 );
        P( A, B, C, D, X[ 3],  3 );
        P( D, A, B, C, X[11],  9 );
        P( C, D, A, B, X[ 7], 11 );
        P( B, C, D, A, X[15], 15 );

    #undef F
    #undef P

        ctx->state[0] += A;
        ctx->state[1] += B;
        ctx->state[2] += C;
        ctx->state[3] += D;
    }

    void md4_starts (struct md4_ctx* ctx) 
    { 
        ctx->total[0] = 0;
        ctx->total[1] = 0;

        ctx->state[0] = 0x67452301;
        ctx->state[1] = 0xEFCDAB89;
        ctx->state[2] = 0x98BADCFE;
        ctx->state[3] = 0x10325476;
    }

    void md4_update (struct md4_ctx* ctx, uint8_t* data, uint32_t dlen)
    { 
        uint32_t fill;
        uint32_t left;

        if( dlen == 0 )
            { return; }

        left = ctx->total[0] & 0x3F;
        fill = 64 - left;

        ctx->total[0] += (uint32_t) dlen;
        ctx->total[0] &= 0xFFFFFFFF;

        if( ctx->total[0] < (uint32_t) dlen )
            ctx->total[1]++;

        if( left && dlen >= fill )
        {
            zmcrypto_memcpy( (void *) (ctx->buffer + left),
                    (void *) data, fill );
            md4_process( ctx, ctx->buffer );
            data += fill;
            dlen  -= fill;
            left = 0;
        }

        while( dlen >= 64 )
        {
            md4_process( ctx, data );
            data += 64;
            dlen  -= 64;
        }

        if( dlen > 0 )
        {
            zmcrypto_memcpy( (void *) (ctx->buffer + left), (void *) data, dlen );
        }
    }

    static const unsigned char md4_padding[64] =
    {
     0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    void md4_final (struct md4_ctx* ctx, uint8_t* output)
    {
        uint32_t last, padn;
        uint32_t high, low;
        uint8_t msglen[8];

        high = ( ctx->total[0] >> 29 )
             | ( ctx->total[1] <<  3 );
        low  = ( ctx->total[0] <<  3 );

        PUT_UINT32_LE( low,  msglen, 0 );
        PUT_UINT32_LE( high, msglen, 4 );

        last = ctx->total[0] & 0x3F;
        padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

        md4_update( ctx, (unsigned char *) md4_padding, padn );
        md4_update( ctx, msglen, 8 );

        PUT_UINT32_LE( ctx->state[0], output,  0 );
        PUT_UINT32_LE( ctx->state[1], output,  4 );
        PUT_UINT32_LE( ctx->state[2], output,  8 );
        PUT_UINT32_LE( ctx->state[3], output, 12 );
    }

#endif /* ZMCRYPTO_ALGO_MD4 */
