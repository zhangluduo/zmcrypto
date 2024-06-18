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
 *   Date: Sep. 2003
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/**
 * Some codes is from the PolarSSL 1.3.9 library, 
 * and adapted for ZmCrypto library by Zhang Luduo.
 */

#include "sm3.h"
#include "debug.h"

#if defined ZMCRYPTO_ALGO_SM3

    struct sm3_ctx
    {
        uint32_t total[2];     /*!< number of bytes processed  */
        uint32_t state[8];     /*!< intermediate digest state  */
        uint8_t buffer[64];    /*!< data block being processed */
    } ;
    
    /* private BEGIN */
    static void sm3_process(struct sm3_ctx *ctx, uint8_t data[64] )
    {
        uint32_t SS1, SS2, TT1, TT2, W[68],W1[64];
        uint32_t A, B, C, D, E, F, G, H;
        uint32_t T[64];
        uint32_t Temp1,Temp2,Temp3,Temp4,Temp5;
        uint32_t j;

        for(j = 0; j < 16; j++)
            { T[j] = 0x79CC4519; }
        for(j =16; j < 64; j++)
            { T[j] = 0x7A879D8A; }

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

        #define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
        #define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

        #define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
        #define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

        #define P0(x) ((x) ^  ROTL32((x),9) ^ ROTL32((x),17)) 
        #define P1(x) ((x) ^  ROTL32((x),15) ^ ROTL32((x),23)) 

        for(j = 16; j < 68; j++ )
        {
            //W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL3232(W[j-3],15)) ^ ROTL3232(W[j - 13],7 ) ^ W[j-6];
            //Why thd release's result is different with the debug's ?
            //Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.
            
            Temp1 = W[j-16] ^ W[j-9];
            Temp2 = ROTL32(W[j-3],15);
            Temp3 = Temp1 ^ Temp2;
            Temp4 = P1(Temp3);
            Temp5 =  ROTL32(W[j - 13],7 ) ^ W[j-6];
            W[j] = Temp4 ^ Temp5;
        }

        for(j =  0; j < 64; j++)
        {
            W1[j] = W[j] ^ W[j+4];
        }

        A = ctx->state[0];
        B = ctx->state[1];
        C = ctx->state[2];
        D = ctx->state[3];
        E = ctx->state[4];
        F = ctx->state[5];
        G = ctx->state[6];
        H = ctx->state[7];

        for(j =0; j < 16; j++)
        {
            SS1 = ROTL32((ROTL32(A,12) + E + ROTL32(T[j],j)), 7); 
            SS2 = SS1 ^ ROTL32(A,12);
            TT1 = FF0(A,B,C) + D + SS2 + W1[j];
            TT2 = GG0(E,F,G) + H + SS1 + W[j];
            D = C;
            C = ROTL32(B,9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F,19);
            F = E;
            E = P0(TT2);
        }
        
        for(j =16; j < 64; j++)
        {
            SS1 = ROTL32((ROTL32(A,12) + E + ROTL32(T[j],j)), 7); 
            SS2 = SS1 ^ ROTL32(A,12);
            TT1 = FF1(A,B,C) + D + SS2 + W1[j];
            TT2 = GG1(E,F,G) + H + SS1 + W[j];
            D = C;
            C = ROTL32(B,9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F,19);
            F = E;
            E = P0(TT2);
        }

        ctx->state[0] ^= A;
        ctx->state[1] ^= B;
        ctx->state[2] ^= C;
        ctx->state[3] ^= D;
        ctx->state[4] ^= E;
        ctx->state[5] ^= F;
        ctx->state[6] ^= G;
        ctx->state[7] ^= H;
    }

    static const uint8_t sm3_padding[64] =
    {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    /* private END */

    struct sm3_ctx* sm3_new (void)
    {
        struct sm3_ctx* ctx = (struct sm3_ctx*)zmcrypto_malloc(sizeof(struct sm3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sm3_ctx));
        return ctx;
    }

    void sm3_free (struct sm3_ctx* ctx)
    {
        zmcrypto_free(ctx);
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
        zmcrypto_memset(ctx, 0, sizeof(struct sm3_ctx));
    }

    void sm3_starts (struct sm3_ctx* ctx)
    {
        ctx->total[0] = 0;
        ctx->total[1] = 0;

        ctx->state[0] = 0x7380166F;
        ctx->state[1] = 0x4914B2B9;
        ctx->state[2] = 0x172442D7;
        ctx->state[3] = 0xDA8A0600;
        ctx->state[4] = 0xA96F30BC;
        ctx->state[5] = 0x163138AA;
        ctx->state[6] = 0xE38DEE4D;
        ctx->state[7] = 0xB0FB0E4E;
    }

    void sm3_update (struct sm3_ctx* ctx, uint8_t* data, uint32_t dsize)
    {
        uint32_t fill, left;

        if (dsize == 0)
            { return; }

        left = ctx->total[0] & 0x3F;
        fill = 64 - left;

        ctx->total[0] += dsize;
        ctx->total[0] &= 0xFFFFFFFF;

        if (ctx->total[0] < (unsigned int) dsize)
            { ctx->total[1]++; }

        if (left && dsize >= fill)
        {
            (void)zmcrypto_memcpy( (void *) (ctx->buffer + left), (void *) data, fill );
            sm3_process( ctx, ctx->buffer );
            data += fill;
            dsize  -= fill;
            left = 0;
        }

        while( dsize >= 64 )
        {
            sm3_process( ctx, data );
            data += 64;
            dsize  -= 64;
        }

        if (dsize > 0)
            { (void)zmcrypto_memcpy( (void *) (ctx->buffer + left), (void *) data, dsize ); }
    }

    void sm3_final (struct sm3_ctx* ctx, uint8_t output[32])
    {
        uint32_t last, padn;
        uint32_t high, low;
        uint8_t msglen[8];

        high = ( ctx->total[0] >> 29 ) | ( ctx->total[1] <<  3 );
        low  = ( ctx->total[0] <<  3 );

        PUT_UINT32_BE( high, msglen, 0 );
        PUT_UINT32_BE( low,  msglen, 4 );

        last = ctx->total[0] & 0x3F;
        padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

        sm3_update( ctx, (uint8_t*) sm3_padding, padn );
        sm3_update( ctx, msglen, 8 );

        PUT_UINT32_BE( ctx->state[0], output,  0 );
        PUT_UINT32_BE( ctx->state[1], output,  4 );
        PUT_UINT32_BE( ctx->state[2], output,  8 );
        PUT_UINT32_BE( ctx->state[3], output, 12 );
        PUT_UINT32_BE( ctx->state[4], output, 16 );
        PUT_UINT32_BE( ctx->state[5], output, 20 );
        PUT_UINT32_BE( ctx->state[6], output, 24 );
        PUT_UINT32_BE( ctx->state[7], output, 28 );
    }

#endif /* ZMCRYPTO_ALGO_SM3 */
