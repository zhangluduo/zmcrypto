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
 *   Date: Mar. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/**
 * Some codes is from the PolarSSL 1.3.9 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

#include "sha2.h"

#if defined ZMCRYPTO_ALGO_SHA2

    struct sha2_ctx
    {
        uint64_t total[2];          /*!< number of bytes processed  */
        uint64_t state[8];          /*!< intermediate digest state  */
        uint8_t buffer[128];        /*!< data block being processed */
    } ;

    static const uint8_t sha256_padding[64] =
    {
     0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    static const uint8_t sha512_padding[128] =
    {
     0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    /*
    * Round constants
    */
    static const uint64_t K[80] =
    {
        CONST64(0x428A2F98D728AE22),  CONST64(0x7137449123EF65CD),
        CONST64(0xB5C0FBCFEC4D3B2F),  CONST64(0xE9B5DBA58189DBBC),
        CONST64(0x3956C25BF348B538),  CONST64(0x59F111F1B605D019),
        CONST64(0x923F82A4AF194F9B),  CONST64(0xAB1C5ED5DA6D8118),
        CONST64(0xD807AA98A3030242),  CONST64(0x12835B0145706FBE),
        CONST64(0x243185BE4EE4B28C),  CONST64(0x550C7DC3D5FFB4E2),
        CONST64(0x72BE5D74F27B896F),  CONST64(0x80DEB1FE3B1696B1),
        CONST64(0x9BDC06A725C71235),  CONST64(0xC19BF174CF692694),
        CONST64(0xE49B69C19EF14AD2),  CONST64(0xEFBE4786384F25E3),
        CONST64(0x0FC19DC68B8CD5B5),  CONST64(0x240CA1CC77AC9C65),
        CONST64(0x2DE92C6F592B0275),  CONST64(0x4A7484AA6EA6E483),
        CONST64(0x5CB0A9DCBD41FBD4),  CONST64(0x76F988DA831153B5),
        CONST64(0x983E5152EE66DFAB),  CONST64(0xA831C66D2DB43210),
        CONST64(0xB00327C898FB213F),  CONST64(0xBF597FC7BEEF0EE4),
        CONST64(0xC6E00BF33DA88FC2),  CONST64(0xD5A79147930AA725),
        CONST64(0x06CA6351E003826F),  CONST64(0x142929670A0E6E70),
        CONST64(0x27B70A8546D22FFC),  CONST64(0x2E1B21385C26C926),
        CONST64(0x4D2C6DFC5AC42AED),  CONST64(0x53380D139D95B3DF),
        CONST64(0x650A73548BAF63DE),  CONST64(0x766A0ABB3C77B2A8),
        CONST64(0x81C2C92E47EDAEE6),  CONST64(0x92722C851482353B),
        CONST64(0xA2BFE8A14CF10364),  CONST64(0xA81A664BBC423001),
        CONST64(0xC24B8B70D0F89791),  CONST64(0xC76C51A30654BE30),
        CONST64(0xD192E819D6EF5218),  CONST64(0xD69906245565A910),
        CONST64(0xF40E35855771202A),  CONST64(0x106AA07032BBD1B8),
        CONST64(0x19A4C116B8D2D0C8),  CONST64(0x1E376C085141AB53),
        CONST64(0x2748774CDF8EEB99),  CONST64(0x34B0BCB5E19B48A8),
        CONST64(0x391C0CB3C5C95A63),  CONST64(0x4ED8AA4AE3418ACB),
        CONST64(0x5B9CCA4F7763E373),  CONST64(0x682E6FF3D6B2B8A3),
        CONST64(0x748F82EE5DEFB2FC),  CONST64(0x78A5636F43172F60),
        CONST64(0x84C87814A1F0AB72),  CONST64(0x8CC702081A6439EC),
        CONST64(0x90BEFFFA23631E28),  CONST64(0xA4506CEBDE82BDE9),
        CONST64(0xBEF9A3F7B2C67915),  CONST64(0xC67178F2E372532B),
        CONST64(0xCA273ECEEA26619C),  CONST64(0xD186B8C721C0C207),
        CONST64(0xEADA7DD6CDE0EB1E),  CONST64(0xF57D4F7FEE6ED178),
        CONST64(0x06F067AA72176FBA),  CONST64(0x0A637DC5A2C898A6),
        CONST64(0x113F9804BEF90DAE),  CONST64(0x1B710B35131C471B),
        CONST64(0x28DB77F523047D84),  CONST64(0x32CAAB7B40C72493),
        CONST64(0x3C9EBE0A15C9BEBC),  CONST64(0x431D67C49C100D4C),
        CONST64(0x4CC5D4BECB3E42B6),  CONST64(0x597F299CFC657E2A),
        CONST64(0x5FCB6FAB3AD6FAEC),  CONST64(0x6C44198C4A475817)
    };

    void sha256_process(struct sha2_ctx *ctx, const uint8_t data[64])
    {
        uint64_t temp1, temp2, W[64];
        uint64_t A, B, C, D, E, F, G, H;

        GET_UINT32_BE( W[ 0], data,  0 );
        GET_UINT32_BE( W[ 1], data,  4 );
        GET_UINT32_BE( W[ 2], data,  8 );
        GET_UINT32_BE( W[ 3], data, 12 );
        GET_UINT32_BE( W[ 4], data, 16 );
        GET_UINT32_BE( W[ 5], data, 20 );
        GET_UINT32_BE( W[ 6], data, 24 );
        GET_UINT32_BE( W[ 7], data, 28 );
        GET_UINT32_BE( W[ 8], data, 32 );
        GET_UINT32_BE( W[ 9], data, 36 );
        GET_UINT32_BE( W[10], data, 40 );
        GET_UINT32_BE( W[11], data, 44 );
        GET_UINT32_BE( W[12], data, 48 );
        GET_UINT32_BE( W[13], data, 52 );
        GET_UINT32_BE( W[14], data, 56 );
        GET_UINT32_BE( W[15], data, 60 );

        #undef SHR
        #undef ROTR
        #undef S0
        #undef S1
        #undef S2
        #undef S3
        #undef F0
        #undef F1

        #define SHR(x,n) ((x & 0xFFFFFFFF) >> n)
        #define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))
        #define S0(x) (ROTR(x, 7) ^ ROTR(x,18) ^  SHR(x, 3))
        #define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^  SHR(x,10))
        #define S2(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
        #define S3(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))

        #define F0(x,y,z) ((x & y) | (z & (x | y)))
        #define F1(x,y,z) (z ^ (x & (y ^ z)))

        #undef R
        #define R(t)                                    \
        (                                               \
            W[t] = S1(W[t -  2]) + W[t -  7] +          \
                S0(W[t - 15]) + W[t - 16]               \
        )

        #undef P
        #define P(a,b,c,d,e,f,g,h,x,K)                  \
        {                                               \
            temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
            temp2 = S2(a) + F0(a,b,c);                  \
            d += temp1; h = temp1 + temp2;              \
        }

        A = ctx->state[0];
        B = ctx->state[1];
        C = ctx->state[2];
        D = ctx->state[3];
        E = ctx->state[4];
        F = ctx->state[5];
        G = ctx->state[6];
        H = ctx->state[7];

        P( A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98 );
        P( H, A, B, C, D, E, F, G, W[ 1], 0x71374491 );
        P( G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCF );
        P( F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA5 );
        P( E, F, G, H, A, B, C, D, W[ 4], 0x3956C25B );
        P( D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1 );
        P( C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4 );
        P( B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5 );
        P( A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98 );
        P( H, A, B, C, D, E, F, G, W[ 9], 0x12835B01 );
        P( G, H, A, B, C, D, E, F, W[10], 0x243185BE );
        P( F, G, H, A, B, C, D, E, W[11], 0x550C7DC3 );
        P( E, F, G, H, A, B, C, D, W[12], 0x72BE5D74 );
        P( D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE );
        P( C, D, E, F, G, H, A, B, W[14], 0x9BDC06A7 );
        P( B, C, D, E, F, G, H, A, W[15], 0xC19BF174 );
        P( A, B, C, D, E, F, G, H, R(16), 0xE49B69C1 );
        P( H, A, B, C, D, E, F, G, R(17), 0xEFBE4786 );
        P( G, H, A, B, C, D, E, F, R(18), 0x0FC19DC6 );
        P( F, G, H, A, B, C, D, E, R(19), 0x240CA1CC );
        P( E, F, G, H, A, B, C, D, R(20), 0x2DE92C6F );
        P( D, E, F, G, H, A, B, C, R(21), 0x4A7484AA );
        P( C, D, E, F, G, H, A, B, R(22), 0x5CB0A9DC );
        P( B, C, D, E, F, G, H, A, R(23), 0x76F988DA );
        P( A, B, C, D, E, F, G, H, R(24), 0x983E5152 );
        P( H, A, B, C, D, E, F, G, R(25), 0xA831C66D );
        P( G, H, A, B, C, D, E, F, R(26), 0xB00327C8 );
        P( F, G, H, A, B, C, D, E, R(27), 0xBF597FC7 );
        P( E, F, G, H, A, B, C, D, R(28), 0xC6E00BF3 );
        P( D, E, F, G, H, A, B, C, R(29), 0xD5A79147 );
        P( C, D, E, F, G, H, A, B, R(30), 0x06CA6351 );
        P( B, C, D, E, F, G, H, A, R(31), 0x14292967 );
        P( A, B, C, D, E, F, G, H, R(32), 0x27B70A85 );
        P( H, A, B, C, D, E, F, G, R(33), 0x2E1B2138 );
        P( G, H, A, B, C, D, E, F, R(34), 0x4D2C6DFC );
        P( F, G, H, A, B, C, D, E, R(35), 0x53380D13 );
        P( E, F, G, H, A, B, C, D, R(36), 0x650A7354 );
        P( D, E, F, G, H, A, B, C, R(37), 0x766A0ABB );
        P( C, D, E, F, G, H, A, B, R(38), 0x81C2C92E );
        P( B, C, D, E, F, G, H, A, R(39), 0x92722C85 );
        P( A, B, C, D, E, F, G, H, R(40), 0xA2BFE8A1 );
        P( H, A, B, C, D, E, F, G, R(41), 0xA81A664B );
        P( G, H, A, B, C, D, E, F, R(42), 0xC24B8B70 );
        P( F, G, H, A, B, C, D, E, R(43), 0xC76C51A3 );
        P( E, F, G, H, A, B, C, D, R(44), 0xD192E819 );
        P( D, E, F, G, H, A, B, C, R(45), 0xD6990624 );
        P( C, D, E, F, G, H, A, B, R(46), 0xF40E3585 );
        P( B, C, D, E, F, G, H, A, R(47), 0x106AA070 );
        P( A, B, C, D, E, F, G, H, R(48), 0x19A4C116 );
        P( H, A, B, C, D, E, F, G, R(49), 0x1E376C08 );
        P( G, H, A, B, C, D, E, F, R(50), 0x2748774C );
        P( F, G, H, A, B, C, D, E, R(51), 0x34B0BCB5 );
        P( E, F, G, H, A, B, C, D, R(52), 0x391C0CB3 );
        P( D, E, F, G, H, A, B, C, R(53), 0x4ED8AA4A );
        P( C, D, E, F, G, H, A, B, R(54), 0x5B9CCA4F );
        P( B, C, D, E, F, G, H, A, R(55), 0x682E6FF3 );
        P( A, B, C, D, E, F, G, H, R(56), 0x748F82EE );
        P( H, A, B, C, D, E, F, G, R(57), 0x78A5636F );
        P( G, H, A, B, C, D, E, F, R(58), 0x84C87814 );
        P( F, G, H, A, B, C, D, E, R(59), 0x8CC70208 );
        P( E, F, G, H, A, B, C, D, R(60), 0x90BEFFFA );
        P( D, E, F, G, H, A, B, C, R(61), 0xA4506CEB );
        P( C, D, E, F, G, H, A, B, R(62), 0xBEF9A3F7 );
        P( B, C, D, E, F, G, H, A, R(63), 0xC67178F2 );

        ctx->state[0] += A;
        ctx->state[1] += B;
        ctx->state[2] += C;
        ctx->state[3] += D;
        ctx->state[4] += E;
        ctx->state[5] += F;
        ctx->state[6] += G;
        ctx->state[7] += H;
    }

    void sha512_process(struct sha2_ctx *ctx, const uint8_t data[128])
    {
        uint32_t i;
        uint64_t temp1, temp2, W[80];
        uint64_t A, B, C, D, E, F, G, H;

        #undef SHR
        #undef ROTR
        #undef S0
        #undef S1
        #undef S2
        #undef S3
        #undef F0
        #undef F1

        #define SHR(x,n) (x >> n)
        #define ROTR(x,n) (SHR(x,n) | (x << (64 - n)))
        #define S0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^  SHR(x, 7))
        #define S1(x) (ROTR(x,19) ^ ROTR(x,61) ^  SHR(x, 6))
        #define S2(x) (ROTR(x,28) ^ ROTR(x,34) ^ ROTR(x,39))
        #define S3(x) (ROTR(x,14) ^ ROTR(x,18) ^ ROTR(x,41))
        #define F0(x,y,z) ((x & y) | (z & (x | y)))
        #define F1(x,y,z) (z ^ (x & (y ^ z)))

        #undef P
        #define P(a,b,c,d,e,f,g,h,x,K)                  \
        {                                               \
            temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
            temp2 = S2(a) + F0(a,b,c);                  \
            d += temp1; h = temp1 + temp2;              \
        }

        for( i = 0; i < 16; i++ )
        {
            GET_UINT64_BE( W[i], data, i << 3 );
        }

        for( ; i < 80; i++ )
        {
            W[i] = S1(W[i -  2]) + W[i -  7] +
                S0(W[i - 15]) + W[i - 16];
        }

        A = ctx->state[0];
        B = ctx->state[1];
        C = ctx->state[2];
        D = ctx->state[3];
        E = ctx->state[4];
        F = ctx->state[5];
        G = ctx->state[6];
        H = ctx->state[7];
        i = 0;

        do
        {
            P( A, B, C, D, E, F, G, H, W[i], K[i] ); i++;
            P( H, A, B, C, D, E, F, G, W[i], K[i] ); i++;
            P( G, H, A, B, C, D, E, F, W[i], K[i] ); i++;
            P( F, G, H, A, B, C, D, E, W[i], K[i] ); i++;
            P( E, F, G, H, A, B, C, D, W[i], K[i] ); i++;
            P( D, E, F, G, H, A, B, C, W[i], K[i] ); i++;
            P( C, D, E, F, G, H, A, B, W[i], K[i] ); i++;
            P( B, C, D, E, F, G, H, A, W[i], K[i] ); i++;
        }
        while( i < 80 );

        ctx->state[0] += A;
        ctx->state[1] += B;
        ctx->state[2] += C;
        ctx->state[3] += D;
        ctx->state[4] += E;
        ctx->state[5] += F;
        ctx->state[6] += G;
        ctx->state[7] += H;
    }

    struct sha224_ctx* sha224_new (void)
    {
        struct sha2_ctx* ctx = (struct sha2_ctx*)zmcrypto_malloc(sizeof(struct sha2_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx));
        return (struct sha224_ctx*)ctx;
    }

    void sha224_free (struct sha224_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t sha224_digest_size (void)
        { return 28; }

    int32_t sha224_block_size (void)
        { return 64; }

    void sha224_init (struct sha224_ctx* ctx)
        { zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx)); }

    void sha224_starts (struct sha224_ctx* ctx)
    {
        ((struct sha2_ctx*)ctx)->total[0] = 0;
        ((struct sha2_ctx*)ctx)->total[1] = 0;

        ((struct sha2_ctx*)ctx)->state[0] = 0xC1059ED8;
        ((struct sha2_ctx*)ctx)->state[1] = 0x367CD507;
        ((struct sha2_ctx*)ctx)->state[2] = 0x3070DD17;
        ((struct sha2_ctx*)ctx)->state[3] = 0xF70E5939;
        ((struct sha2_ctx*)ctx)->state[4] = 0xFFC00B31;
        ((struct sha2_ctx*)ctx)->state[5] = 0x68581511;
        ((struct sha2_ctx*)ctx)->state[6] = 0x64F98FA7;
        ((struct sha2_ctx*)ctx)->state[7] = 0xBEFA4FA4;
    }

    void sha224_update (struct sha224_ctx* ctx, uint8_t* data, uint32_t dlen)
        { sha256_update ((struct sha256_ctx*)ctx, data, dlen); }

    void sha224_final (struct sha224_ctx* ctx, uint8_t* output)
    {
        uint32_t last, padn;
        uint32_t high, low;
        uint8_t msglen[8];

        high = (uint32_t)(( ((struct sha2_ctx*)ctx)->total[0] >> 29 )
                        | ( ((struct sha2_ctx*)ctx)->total[1] <<  3 ));
        low  = (uint32_t)(( ((struct sha2_ctx*)ctx)->total[0] <<  3 ));

        PUT_UINT32_BE( high, msglen, 0 );
        PUT_UINT32_BE( low,  msglen, 4 );

        last = ((struct sha2_ctx*)ctx)->total[0] & 0x3F;
        padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

        sha256_update( ((struct sha256_ctx*)ctx), (uint8_t*)sha256_padding, padn );
        sha256_update( ((struct sha256_ctx*)ctx), msglen, 8 );

        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[0], output,  0 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[1], output,  4 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[2], output,  8 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[3], output, 12 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[4], output, 16 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[5], output, 20 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[6], output, 24 );
    }

    struct sha256_ctx* sha256_new (void)
    {
        struct sha2_ctx* ctx = (struct sha2_ctx*)zmcrypto_malloc(sizeof(struct sha2_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx));
        return (struct sha256_ctx*)ctx;
    }

    void sha256_free (struct sha256_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }
    
    int32_t sha256_digest_size (void)
        { return 32; }

    int32_t sha256_block_size (void)
        { return 64; }

    void sha256_init (struct sha256_ctx* ctx)
        { zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx)); }

    void sha256_starts (struct sha256_ctx* ctx)
    {
        ((struct sha2_ctx*)ctx)->total[0] = 0;
        ((struct sha2_ctx*)ctx)->total[1] = 0;

        ((struct sha2_ctx*)ctx)->state[0] = 0x6A09E667;
        ((struct sha2_ctx*)ctx)->state[1] = 0xBB67AE85;
        ((struct sha2_ctx*)ctx)->state[2] = 0x3C6EF372;
        ((struct sha2_ctx*)ctx)->state[3] = 0xA54FF53A;
        ((struct sha2_ctx*)ctx)->state[4] = 0x510E527F;
        ((struct sha2_ctx*)ctx)->state[5] = 0x9B05688C;
        ((struct sha2_ctx*)ctx)->state[6] = 0x1F83D9AB;
        ((struct sha2_ctx*)ctx)->state[7] = 0x5BE0CD19;
    }

    void sha256_update (struct sha256_ctx* ctx, uint8_t* data, uint32_t dlen)
    {
        uint32_t fill;
        uint32_t left;

        if (dlen == 0 )
            { return; }

        left = ((struct sha2_ctx*)ctx)->total[0] & 0x3F;
        fill = 64 - left;

        ((struct sha2_ctx*)ctx)->total[0] += (uint32_t) dlen;
        ((struct sha2_ctx*)ctx)->total[0] &= 0xFFFFFFFF;

        if ( ((struct sha2_ctx*)ctx)->total[0] < (uint32_t) dlen )
            { ((struct sha2_ctx*)ctx)->total[1]++; }

        if ( left && dlen >= fill )
        {
            zmcrypto_memcpy( (void *) (((struct sha2_ctx*)ctx)->buffer + left), data, fill );
            sha256_process( ((struct sha2_ctx*)ctx), ((struct sha2_ctx*)ctx)->buffer );
            data += fill;
            dlen -= fill;
            left = 0;
        }

        while ( dlen >= 64 )
        {
            sha256_process( ((struct sha2_ctx*)ctx), data );
            data += 64;
            dlen -= 64;
        }

        if( dlen > 0 )
            { zmcrypto_memcpy( (void *) (((struct sha2_ctx*)ctx)->buffer + left), data, dlen ); }
    }

    void sha256_final (struct sha256_ctx* ctx, uint8_t* output)
    {
        uint32_t last, padn;
        uint32_t high, low;
        uint8_t msglen[8];

        high = (uint32_t)(( ((struct sha2_ctx*)ctx)->total[0] >> 29 )
                        | ( ((struct sha2_ctx*)ctx)->total[1] <<  3 ));
        low  = (uint32_t)(( ((struct sha2_ctx*)ctx)->total[0] <<  3 ));

        PUT_UINT32_BE( high, msglen, 0 );
        PUT_UINT32_BE( low,  msglen, 4 );

        last = ((struct sha2_ctx*)ctx)->total[0] & 0x3F;
        padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

        sha256_update( ((struct sha256_ctx*)ctx), (uint8_t*)sha256_padding, padn );
        sha256_update( ((struct sha256_ctx*)ctx), msglen, 8 );

        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[0], output,  0 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[1], output,  4 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[2], output,  8 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[3], output, 12 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[4], output, 16 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[5], output, 20 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[6], output, 24 );
        PUT_UINT32_BE( ((struct sha2_ctx*)ctx)->state[7], output, 28 );
    }

    struct sha384_ctx* sha384_new (void)
    {
        struct sha2_ctx* ctx = (struct sha2_ctx*)zmcrypto_malloc(sizeof(struct sha2_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx));
        return (struct sha384_ctx*)ctx;
    }

    void sha384_free (struct sha384_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }
    
    int32_t sha384_digest_size (void)
        { return 48; }

    int32_t sha384_block_size (void)
        { return 128; }

    void sha384_init (struct sha384_ctx* ctx)
        { zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx)); }

    void sha384_starts (struct sha384_ctx* ctx)
    {
        ((struct sha2_ctx*)ctx)->total[0] = 0;
        ((struct sha2_ctx*)ctx)->total[1] = 0;

        ((struct sha2_ctx*)ctx)->state[0] = CONST64(0xCBBB9D5DC1059ED8);
        ((struct sha2_ctx*)ctx)->state[1] = CONST64(0x629A292A367CD507);
        ((struct sha2_ctx*)ctx)->state[2] = CONST64(0x9159015A3070DD17);
        ((struct sha2_ctx*)ctx)->state[3] = CONST64(0x152FECD8F70E5939);
        ((struct sha2_ctx*)ctx)->state[4] = CONST64(0x67332667FFC00B31);
        ((struct sha2_ctx*)ctx)->state[5] = CONST64(0x8EB44A8768581511);
        ((struct sha2_ctx*)ctx)->state[6] = CONST64(0xDB0C2E0D64F98FA7);
        ((struct sha2_ctx*)ctx)->state[7] = CONST64(0x47B5481DBEFA4FA4);
    }

    void sha384_update (struct sha384_ctx* ctx, uint8_t* data, uint32_t dlen)
        { sha512_update ((struct sha512_ctx*)ctx, data, dlen); }

    void sha384_final (struct sha384_ctx* ctx, uint8_t* output)
    {
        uint64_t last, padn;
        uint64_t high, low;
        uint8_t msglen[16];

        high = ( ((struct sha2_ctx*)ctx)->total[0] >> 61 )
             | ( ((struct sha2_ctx*)ctx)->total[1] <<  3 );
        low  = ( ((struct sha2_ctx*)ctx)->total[0] <<  3 );

        PUT_UINT64_BE( high, msglen, 0 );
        PUT_UINT64_BE( low,  msglen, 8 );

        last = (size_t)( ((struct sha2_ctx*)ctx)->total[0] & 0x7F );
        padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

        sha512_update( ((struct sha512_ctx*)ctx), (uint8_t*)sha512_padding, (uint32_t)padn );
        sha512_update( ((struct sha512_ctx*)ctx), msglen, 16 );

        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[0], output,  0 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[1], output,  8 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[2], output, 16 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[3], output, 24 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[4], output, 32 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[5], output, 40 );
    }

    struct sha512_ctx* sha512_new (void)
    {
        struct sha2_ctx* ctx = (struct sha2_ctx*)zmcrypto_malloc(sizeof(struct sha2_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx));
        return (struct sha512_ctx*)ctx;
    }

    void sha512_free (struct sha512_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }
    
    int32_t sha512_digest_size (void)
        { return 64; }

    int32_t sha512_block_size (void)
        { return 128; }

    void sha512_init (struct sha512_ctx* ctx)
        { zmcrypto_memset(ctx, 0, sizeof(struct sha2_ctx)); }

    void sha512_starts (struct sha512_ctx* ctx)
    {
        ((struct sha2_ctx*)ctx)->total[0] = 0;
        ((struct sha2_ctx*)ctx)->total[1] = 0;

        ((struct sha2_ctx*)ctx)->state[0] = CONST64(0x6A09E667F3BCC908);
        ((struct sha2_ctx*)ctx)->state[1] = CONST64(0xBB67AE8584CAA73B);
        ((struct sha2_ctx*)ctx)->state[2] = CONST64(0x3C6EF372FE94F82B);
        ((struct sha2_ctx*)ctx)->state[3] = CONST64(0xA54FF53A5F1D36F1);
        ((struct sha2_ctx*)ctx)->state[4] = CONST64(0x510E527FADE682D1);
        ((struct sha2_ctx*)ctx)->state[5] = CONST64(0x9B05688C2B3E6C1F);
        ((struct sha2_ctx*)ctx)->state[6] = CONST64(0x1F83D9ABFB41BD6B);
        ((struct sha2_ctx*)ctx)->state[7] = CONST64(0x5BE0CD19137E2179);
    }

    void sha512_update (struct sha512_ctx* ctx, uint8_t* data, uint32_t dlen)
    {
        uint32_t fill;
        uint32_t left;

        if (dlen == 0)
            { return; }

        left = (uint32_t) (((struct sha2_ctx*)ctx)->total[0] & 0x7F);
        fill = 128 - left;

        ((struct sha2_ctx*)ctx)->total[0] += (uint64_t) dlen;

        if( ((struct sha2_ctx*)ctx)->total[0] < (uint64_t) dlen )
            { ((struct sha2_ctx*)ctx)->total[1]++; }

        if( left && dlen >= fill )
        {
            zmcrypto_memcpy( (void *) (((struct sha2_ctx*)ctx)->buffer + left), data, fill );
            sha512_process( ((struct sha2_ctx*)ctx), ((struct sha2_ctx*)ctx)->buffer );
            data += fill;
            dlen -= fill;
            left = 0;
        }

        while( dlen >= 128 )
        {
            sha512_process( ((struct sha2_ctx*)ctx), data );
            data += 128;
            dlen -= 128;
        }

        if( dlen > 0 )
            { zmcrypto_memcpy( (void *) (((struct sha2_ctx*)ctx)->buffer + left), data, dlen ); }
    }

    void sha512_final (struct sha512_ctx* ctx, uint8_t* output)
    {
        uint64_t last, padn;
        uint64_t high, low;
        uint8_t msglen[16];

        high = ( ((struct sha2_ctx*)ctx)->total[0] >> 61 )
             | ( ((struct sha2_ctx*)ctx)->total[1] <<  3 );
        low  = ( ((struct sha2_ctx*)ctx)->total[0] <<  3 );

        PUT_UINT64_BE( high, msglen, 0 );
        PUT_UINT64_BE( low,  msglen, 8 );

        last = (size_t)( ((struct sha2_ctx*)ctx)->total[0] & 0x7F );
        padn = ( last < 112 ) ? ( 112 - last ) : ( 240 - last );

        sha512_update( ((struct sha512_ctx*)ctx), (uint8_t*)sha512_padding, (uint32_t)padn );
        sha512_update( ((struct sha512_ctx*)ctx), msglen, 16 );

        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[0], output,  0 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[1], output,  8 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[2], output, 16 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[3], output, 24 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[4], output, 32 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[5], output, 40 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[6], output, 48 );
        PUT_UINT64_BE( ((struct sha2_ctx*)ctx)->state[7], output, 56 );
    }

#endif /* ZMCRYPTO_ALGO_SHA2 */
