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

#include "sha3.h"

#if defined ZMCRYPTO_ALGO_SHA3

    #define SHA3_224_DIGEST_SIZE   (224 / 8)  //28
    #define SHA3_224_BLOCK_SIZE    (200 - 2 * SHA3_224_DIGEST_SIZE)  //144
    #define SHA3_256_DIGEST_SIZE   (256 / 8)  //32
    #define SHA3_256_BLOCK_SIZE    (200 - 2 * SHA3_256_DIGEST_SIZE)  //136
    #define SHA3_384_DIGEST_SIZE   (384 / 8)  //48
    #define SHA3_384_BLOCK_SIZE    (200 - 2 * SHA3_384_DIGEST_SIZE)  //104
    #define SHA3_512_DIGEST_SIZE   (512 / 8)  //64
    #define SHA3_512_BLOCK_SIZE    (200 - 2 * SHA3_512_DIGEST_SIZE)  //72

    #define SHA3_KECCAK_SPONGE_WORDS 25 /* 1600 bits > 200 bytes > 25 x uint64_t */
    #define SHA3_KECCAK_ROUNDS 24

    static const uint64_t keccakf_rndc[24] = {
        CONST64(0x0000000000000001), CONST64(0x0000000000008082),
        CONST64(0x800000000000808a), CONST64(0x8000000080008000),
        CONST64(0x000000000000808b), CONST64(0x0000000080000001),
        CONST64(0x8000000080008081), CONST64(0x8000000000008009),
        CONST64(0x000000000000008a), CONST64(0x0000000000000088),
        CONST64(0x0000000080008009), CONST64(0x000000008000000a),
        CONST64(0x000000008000808b), CONST64(0x800000000000008b),
        CONST64(0x8000000000008089), CONST64(0x8000000000008003),
        CONST64(0x8000000000008002), CONST64(0x8000000000000080),
        CONST64(0x000000000000800a), CONST64(0x800000008000000a),
        CONST64(0x8000000080008081), CONST64(0x8000000000008080),
        CONST64(0x0000000080000001), CONST64(0x8000000080008008)
    };

    static const unsigned keccakf_rotc[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    static const unsigned keccakf_piln[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    struct sha3_ctx
    {
        uint64_t saved;           /* the portion of the input message that we didn't consume yet */
        uint64_t s[25];
        uint8_t sb[25 * 8];       /* used for storing `uint64_t s[25]` as little-endian bytes */
        uint16_t byte_index;      /* 0..7--the next byte after the set one (starts from 0; 0--none are buffered) */
        uint16_t word_index;      /* 0..24--the next word to integrate input (starts from 0) */
        uint16_t capacity_words;  /* the double size of the hash output in words (e.g. 16 for Keccak 512) */
        uint16_t xof_flag;
    } ;

    static void keccakf(uint64_t s[25])
    {
        int i, j, round;
        uint64_t t, bc[5];

        for(round = 0; round < SHA3_KECCAK_ROUNDS; round++) 
        {
            /* Theta */
            for(i = 0; i < 5; i++)
                { bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20]; }

            for(i = 0; i < 5; i++) 
            {
                t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
                for(j = 0; j < 25; j += 5)
                    { s[j + i] ^= t; }
            }
            /* Rho Pi */
            t = s[1];
            for(i = 0; i < 24; i++) 
            {
                j = keccakf_piln[i];
                bc[0] = s[j];
                s[j] = ROTL64(t, keccakf_rotc[i]);
                t = bc[0];
            }
            /* Chi */
            for(j = 0; j < 25; j += 5) 
            {
                for(i = 0; i < 5; i++)
                    { bc[i] = s[j + i]; }
                for(i = 0; i < 5; i++)
                    { s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5]; }
            }
            /* Iota */
            s[0] ^= keccakf_rndc[round];
        }
    }

    void sha3_process(struct sha3_ctx *ctx, const uint8_t *in, uint32_t inlen)
    {
        /* nothing to do */
        if (inlen == 0) 
            { return; }

        /* 0...7 -- how much is needed to have a word */
        uint32_t old_tail = (8 - ctx->byte_index) & 7;

        uint32_t words;
        uint32_t tail;
        uint32_t i;

        /* have no complete word or haven't started the word yet */
        if (inlen < old_tail) 
        { 
            while (inlen--)
                { ctx->saved |= (uint64_t) (*(in++)) << ((ctx->byte_index++) * 8); }
            return;
        }

        /* will have one word to process */
        if(old_tail)
        {
            inlen -= old_tail;
            while (old_tail--) 
                { ctx->saved |= (uint64_t) (*(in++)) << ((ctx->byte_index++) * 8); }

            /* now ready to add saved to the sponge */
            ctx->s[ctx->word_index] ^= ctx->saved;
            ctx->byte_index = 0;
            ctx->saved = 0;
            if(++ctx->word_index == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacity_words)) 
            {
                keccakf(ctx->s);
                ctx->word_index = 0;
            }
        }

        /* now work in full words directly from input */
        words = inlen / sizeof(uint64_t);
        tail = inlen - words * sizeof(uint64_t);

        for(i = 0; i < words; i++, in += sizeof(uint64_t)) 
        {
            uint64_t t;
            GET_UINT64_LE(t, in, 0);

            ctx->s[ctx->word_index] ^= t;
            if(++ctx->word_index == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacity_words)) 
            {
                keccakf(ctx->s);
                ctx->word_index = 0;
            }
        }

        /* finally, save the partial word */
        while (tail--) 
            { ctx->saved |= (uint64_t) (*(in++)) << ((ctx->byte_index++) * 8); }
    }

    void sha3_done(struct sha3_ctx  *ctx, uint8_t *hash)
    {
        uint32_t i;
        ctx->s[ctx->word_index] ^= (ctx->saved ^ (CONST64(0x06) << (ctx->byte_index * 8)));
        ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacity_words - 1] ^= CONST64(0x8000000000000000);
        keccakf(ctx->s);

        /* store s[] as little-endian bytes into sb */
        for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) 
            { PUT_UINT64_LE(ctx->s[i], ctx->sb + i * 8, 0); }

        zmcrypto_memcpy(hash, ctx->sb, ctx->capacity_words * 4);
    }
        
    struct sha3_224_ctx* sha3_224_new (void)
    { 
        struct sha3_ctx* ctx = (struct sha3_ctx*)zmcrypto_malloc(sizeof(struct sha3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        return (struct sha3_224_ctx*)ctx;     
    }

    void sha3_224_free (struct sha3_224_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t sha3_224_digest_size (void)
        { return SHA3_224_DIGEST_SIZE; }

    int32_t sha3_224_block_size (void)
        { return SHA3_224_BLOCK_SIZE; }

    void sha3_224_init (struct sha3_224_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        ((struct sha3_ctx*)ctx)->capacity_words =  2 * 224 / (8 * sizeof(uint64_t));
    }

    void sha3_224_starts (struct sha3_224_ctx* ctx)
    {  }

    void sha3_224_update (struct sha3_224_ctx* ctx, uint8_t* data, uint32_t dsize)
    {
        sha3_process((struct sha3_ctx*)ctx, data, dsize);
    }

    void sha3_224_final (struct sha3_224_ctx* ctx, uint8_t output[28])
    {
        sha3_done((struct sha3_ctx*)ctx, output);
    }

    struct sha3_256_ctx* sha3_256_new (void)
    { 
        struct sha3_ctx* ctx = (struct sha3_ctx*)zmcrypto_malloc(sizeof(struct sha3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        return (struct sha3_256_ctx*)ctx; 
    }

    void sha3_256_free (struct sha3_256_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t sha3_256_digest_size (void)
        { return SHA3_256_DIGEST_SIZE; }

    int32_t sha3_256_block_size (void) 
        { return SHA3_256_BLOCK_SIZE; }

    void sha3_256_init (struct sha3_256_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        ((struct sha3_ctx*)ctx)->capacity_words =  2 * 256 / (8 * sizeof(uint64_t));
    }

    void sha3_256_starts (struct sha3_256_ctx* ctx)
    {  }

    void sha3_256_update (struct sha3_256_ctx* ctx, uint8_t* data, uint32_t dsize)
    {
        sha3_process((struct sha3_ctx*)ctx, data, dsize);
    }

    void sha3_256_final (struct sha3_256_ctx* ctx, uint8_t output[32])
    {
        sha3_done((struct sha3_ctx*)ctx, output);
    }

    struct sha3_384_ctx* sha3_384_new (void)
    { 
        struct sha3_ctx* ctx = (struct sha3_ctx*)zmcrypto_malloc(sizeof(struct sha3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        return (struct sha3_384_ctx*)ctx;  
    }

    void sha3_384_free (struct sha3_384_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t sha3_384_digest_size (void)
        { return SHA3_384_DIGEST_SIZE; }

    int32_t sha3_384_block_size (void)
        { return SHA3_384_BLOCK_SIZE; }

    void sha3_384_init (struct sha3_384_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        ((struct sha3_ctx*)ctx)->capacity_words =  2 * 384 / (8 * sizeof(uint64_t));
    }

    void sha3_384_starts (struct sha3_384_ctx* ctx)
    {  }

    void sha3_384_update (struct sha3_384_ctx* ctx, uint8_t* data, uint32_t dsize)
    {
        sha3_process((struct sha3_ctx*)ctx, data, dsize);
    }

    void sha3_384_final (struct sha3_384_ctx* ctx, uint8_t output[48])
    {
        sha3_done((struct sha3_ctx*)ctx, output);
    }

    struct sha3_512_ctx* sha3_512_new (void)
    { 
        struct sha3_ctx* ctx = (struct sha3_ctx*)zmcrypto_malloc(sizeof(struct sha3_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        return (struct sha3_512_ctx*)ctx;
    }

    void sha3_512_free (struct sha3_512_ctx* ctx)
    {
        zmcrypto_free(ctx);
    }

    int32_t sha3_512_digest_size (void)
        { return SHA3_512_DIGEST_SIZE; }

    int32_t sha3_512_block_size (void)
        { return SHA3_512_BLOCK_SIZE; }

    void sha3_512_init (struct sha3_512_ctx* ctx)
    {
        zmcrypto_memset(ctx, 0, sizeof(struct sha3_ctx));
        ((struct sha3_ctx*)ctx)->capacity_words =  2 * 512 / (8 * sizeof(uint64_t));
    }

    void sha3_512_starts (struct sha3_512_ctx* ctx)
    {  }

    void sha3_512_update (struct sha3_512_ctx* ctx, uint8_t* data, uint32_t dsize)
    {
        sha3_process((struct sha3_ctx*)ctx, data, dsize);
    }

    void sha3_512_final (struct sha3_512_ctx* ctx, uint8_t output[64])
    {
        sha3_done((struct sha3_ctx*)ctx, output);
    }

#endif /* ZMCRYPTO_ALGO_SHA3 */
