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

/* 
   [GCM]         Dworkin, M., "Recommendation for Block Cipher Modes of
                 Operation: Galois/Counter Mode (GCM) and GMAC",
                 National Institute of Standards and Technology SP 800-
                 38D, November 2007.
*/


/*
 * http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 *
 * See also:
 * [MGV] http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
 *
 * We use the algorithm described as Shoup's method with 4-bit tables in
 * [MGV] 4.1, pp. 12-13, to enhance speed without using too much memory.
 */

#include "gcm.h"

#if defined ZMCRYPTO_ALGO_GCM

    struct gcm_ctx
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

        uint64_t HL[16];                      /*!< Precalculated HTable low. */
        uint64_t HH[16];                      /*!< Precalculated HTable high. */
        uint64_t len;                         /*!< The total length of the encrypted data. */
        uint64_t add_len;                     /*!< The total length of the additional data. */
        uint8_t base_ectr[16];                /*!< The first ECTR for tag. */
        uint8_t y[16];                        /*!< The Y working value. */
        uint8_t buf[16];                      /*!< The buf working value. */
        uint32_t direction;                   /*!< The operation to perform: DO_ENCRYPT or DO_DECRYPT */
    } ;

    /*
    * Shoup's method for multiplication use this table with
    *      last4[x] = x times P^128
    * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
    */
    static const uint64_t last4[16] =
    {
        0x0000, 0x1c20, 0x3840, 0x2460,
        0x7080, 0x6ca0, 0x48c0, 0x54e0,
        0xe100, 0xfd20, 0xd940, 0xc560,
        0x9180, 0x8da0, 0xa9c0, 0xb5e0
    };

    /*
    * Precompute small multiples of H, that is set
    *      HH[i] || HL[i] = H times i,
    * where i is seen as a field element as in [MGV], ie high-order bits
    * correspond to low powers of P. The result is stored in the same way, that
    * is the high-order bit of HH corresponds to P^0 and the low-order bit of HL
    * corresponds to P^127.
    */
    zmerror gcm_gen_table(struct gcm_ctx* ctx)
    {
        if (ctx->cipher_ctx == NULL || ctx->cipher_enc_block == NULL)
        { return ZMCRYPTO_ERR_NULL_PTR; }

        uint64_t hi, lo;
        uint64_t vl, vh;
        uint8_t h[16];

        zmcrypto_memset(h, 0, 16);
        ctx->cipher_enc_block (ctx->cipher_ctx, h, h);

        /* pack h as two 64-bits ints, big-endian */
        GET_UINT32_BE( hi, h,  0  );
        GET_UINT32_BE( lo, h,  4  );
        vh = (uint64_t) hi << 32 | lo;

        GET_UINT32_BE( hi, h,  8  );
        GET_UINT32_BE( lo, h,  12 );
        vl = (uint64_t) hi << 32 | lo;

        /* 8 = 1000 corresponds to 1 in GF(2^128) */
        ctx->HL[8] = vl;
        ctx->HH[8] = vh;

        /* 0 corresponds to 0 in GF(2^128) */
        ctx->HH[0] = 0;
        ctx->HL[0] = 0;


        for (uint32_t i = 4; i > 0; i >>= 1 )
        {
            uint32_t T = ( vl & 1 ) * 0xe1000000U;
            vl  = ( vh << 63 ) | ( vl >> 1 );
            vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);

            ctx->HL[i] = vl;
            ctx->HH[i] = vh;
        }

        for (uint32_t i = 2; i <= 8; i *= 2 )
        {
            uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
            vh = *HiH;
            vl = *HiL;
            for (uint32_t j = 1; j < i; j++ )
            {
                HiH[j] = vh ^ ctx->HH[j];
                HiL[j] = vl ^ ctx->HL[j];
            }
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

   /* Increment the counter. */
   void gcm_incr(uint8_t y[16] )
   {
        for(uint32_t i = 16; i > 12; i-- )
        {
        if( ++y[i - 1] != 0 ) 
            { break; }
        }
   }

    /*
    * Sets output to x times H using the precomputed tables.
    * x and output are seen as elements of GF(2^128) as in [MGV].
    */
    void gcm_mult(struct gcm_ctx* ctx, const uint8_t x[16], uint8_t output[16] )
    {
        int32_t i = 0;
        uint8_t lo, hi, rem;
        uint64_t zh, zl;

        lo = x[15] & 0xf;

        zh = ctx->HH[lo];
        zl = ctx->HL[lo];

        for( i = 15; i >= 0; i-- )
        {
            lo = x[i] & 0xf;
            hi = ( x[i] >> 4 ) & 0xf;

            if( i != 15 )
            {
                rem = (unsigned char) zl & 0xf;
                zl = ( zh << 60 ) | ( zl >> 4 );
                zh = ( zh >> 4 );
                zh ^= (uint64_t) last4[rem] << 48;
                zh ^= ctx->HH[lo];
                zl ^= ctx->HL[lo];
            }

            rem = (unsigned char) zl & 0xf;
            zl = ( zh << 60 ) | ( zl >> 4 );
            zh = ( zh >> 4 );
            zh ^= (uint64_t) last4[rem] << 48;
            zh ^= ctx->HH[hi];
            zl ^= ctx->HL[hi];
        }

        PUT_UINT32_BE( zh >> 32, output, 0 );
        PUT_UINT32_BE( zh, output, 4 );
        PUT_UINT32_BE( zl >> 32, output, 8 );
        PUT_UINT32_BE( zl, output, 12 );
    }

   /* Calculate and apply the encryption mask. Process use_len bytes of data,
   * starting at position offset in the mask block. */
   zmerror gcm_mask(struct gcm_ctx* ctx, uint8_t ectr[16], uint64_t offset, uint32_t use_len,
      const uint8_t *input,  uint8_t *output )
   {
        if (ctx->cipher_ctx == NULL || ctx->cipher_enc_block == NULL)
            { return ZMCRYPTO_ERR_NULL_PTR; }

        ctx->cipher_enc_block (ctx->cipher_ctx, ctx->y, ectr);

        for(uint32_t i = 0; i < use_len; i++ )
        {
            if ( ctx->direction == DO_DECRYPT )
                { ctx->buf[offset + i] ^= input[i]; }

            output[i] = ectr[offset + i] ^ input[i];

            if ( ctx->direction == DO_ENCRYPT )
                { ctx->buf[offset + i] ^= output[i];}
        }

        return ZMCRYPTO_ERR_SUCCESSED;
   }

   struct gcm_ctx* gcm_new (void)
   {
        struct gcm_ctx* ctx = (struct gcm_ctx*)zmcrypto_malloc(sizeof(struct gcm_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct gcm_ctx));
        return ctx;
   }

    void gcm_free (struct gcm_ctx* ctx)
    {
        if (ctx)
        {
            if (ctx->cipher_ctx)
            {
                ctx->cipher_free(ctx->cipher_ctx);
                ctx->cipher_ctx = NULL;
            }
            zmcrypto_free (ctx);
        }
    }

    void gcm_init (
        struct gcm_ctx* ctx,
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
        void    (*cipher_dec_block)      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
        )
    {
        zmcrypto_memset(ctx, 0, sizeof(struct gcm_ctx));
        ctx->cipher_new            = cipher_new            ;
        ctx->cipher_free           = cipher_free           ;
        ctx->cipher_init           = cipher_init           ;
        ctx->cipher_block_size     = cipher_block_size     ;
        ctx->cipher_ksize_min      = cipher_ksize_min      ;
        ctx->cipher_ksize_max      = cipher_ksize_max      ;
        ctx->cipher_ksize_multiple = cipher_ksize_multiple ;
        ctx->cipher_set_ekey       = cipher_set_ekey       ;
        ctx->cipher_set_dkey       = cipher_set_dkey       ;
        ctx->cipher_enc_block      = cipher_enc_block      ;
        ctx->cipher_dec_block      = cipher_dec_block      ;
        ctx->cipher_ctx = NULL;
    }

    zmerror gcm_starts (
        struct gcm_ctx* ctx,
        uint8_t *key, uint32_t klen,
        uint8_t *iv, uint32_t ivlen,
        uint32_t direction
        )
    {
        if (ivlen == 0)
            { return ZMCRYPTO_ERR_INVALID_IVSIZE; }

        if (ctx->cipher_ctx == NULL)
        {
            ctx->cipher_ctx = ctx->cipher_new(); 
            int32_t ret = ctx->cipher_set_ekey(ctx->cipher_ctx, key, klen);
            if (ret <= 0)
                { return ret; }
        }

        zmcrypto_memset(ctx->y, 0x00, sizeof(ctx->y));
        zmcrypto_memset(ctx->buf, 0x00, sizeof(ctx->buf));

        ctx->direction = direction;
        ctx->len = 0;
        ctx->add_len = 0;

        zmerror err = gcm_gen_table(ctx);
        if (err != ZMCRYPTO_ERR_SUCCESSED)
            { return err; }

        uint8_t work_buf[16];
        const uint8_t *p;
        uint32_t use_len;

        if (ivlen == 12)
        {
            zmcrypto_memcpy(ctx->y, iv, ivlen);
            ctx->y[15] = 1;
        }
        else
        {
            zmcrypto_memset(work_buf, 0x00, 16);
            PUT_UINT32_BE(ivlen * 8, work_buf, 12);

            p = iv;
            while( ivlen > 0 )
            {
                use_len = ( ivlen < 16 ) ? ivlen : 16;

                for(uint32_t i = 0; i < use_len; i++ )
                    { ctx->y[i] ^= p[i]; }

                gcm_mult( ctx, ctx->y, ctx->y );

                ivlen -= use_len;
                p += use_len;
            }

            for(uint32_t i = 0; i < 16; i++ )
                { ctx->y[i] ^= work_buf[i]; }

            gcm_mult( ctx, ctx->y, ctx->y );
        }

        ctx->cipher_enc_block (ctx->cipher_ctx, ctx->y, ctx->base_ectr);
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror gcm_update_aad (
        struct gcm_ctx* ctx,
        uint8_t *aad,  
        uint32_t alen
        )
    {
        if (alen == 0)
            { return ZMCRYPTO_ERR_SUCCESSED; }

        const uint8_t *p;
        uint64_t use_len, i, offset;

        offset = ctx->add_len % 16;
        p = aad;

        if( offset != 0 )
        {
            use_len = 16 - offset;
            if( use_len > alen )
                { use_len = alen; }

            for( i = 0; i < use_len; i++ )
                { ctx->buf[i+offset] ^= p[i]; }

            if( offset + use_len == 16 )
                { gcm_mult( ctx, ctx->buf, ctx->buf ); }

            ctx->add_len += use_len;
            alen -= use_len;
            p += use_len;
        }

        ctx->add_len += alen;

        while( alen >= 16 )
        {
            for( i = 0; i < 16; i++ )
                { ctx->buf[i] ^= p[i]; }

            gcm_mult( ctx, ctx->buf, ctx->buf );

            alen -= 16;
            p += 16;
        }

        if( alen > 0 )
        {
            for( i = 0; i < alen; i++ )
                { ctx->buf[i] ^= p[i]; }
        }

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror gcm_update_data (
        struct gcm_ctx* ctx,
        uint8_t *data, 
        uint32_t dlen, 
        uint8_t *output
        )
    {
        /* Exit early if input_length==0 so that we don't do any pointer arithmetic
        * on a potentially null pointer.
        * Returning early also means that the last partial block of AD remains
        * untouched for gcm_finish */
        if( dlen == 0 )
            { return ZMCRYPTO_ERR_SUCCESSED; }

        /* Total length is restricted to 2^39 - 256 bits, ie 2^36 - 2^5 bytes
        * Also check for possible overflow */
        if( (uint64_t) ctx->len + dlen > 0xFFFFFFFE0ull )
            { return ZMCRYPTO_ERR_OVERFLOW; }

        zmerror ret;
        const uint8_t *p = data;
        uint8_t *out_p = output;
        uint32_t offset;
        uint8_t ectr[16];

        if( ctx->len == 0 && ctx->add_len % 16 != 0 )
        {
            gcm_mult( ctx, ctx->buf, ctx->buf );
        }

        offset = ctx->len % 16;
        if( offset != 0 )
        {
            uint32_t use_len = 16 - offset;
            if( use_len > dlen )
                { use_len = dlen; }

            if( ( ret = gcm_mask( ctx, ectr, offset, use_len, p, out_p ) ) != ZMCRYPTO_ERR_SUCCESSED )
                { return ret; }

            if( offset + use_len == 16 )
                { gcm_mult( ctx, ctx->buf, ctx->buf ); }

            ctx->len += use_len;
            dlen -= use_len;
            p += use_len;
            out_p += use_len;
        }

        ctx->len += dlen;

        while( dlen >= 16 )
        {
            gcm_incr( ctx->y );
            if( ( ret = gcm_mask( ctx, ectr, 0, 16, p, out_p ) ) != ZMCRYPTO_ERR_SUCCESSED )
                { return ret; }

            gcm_mult( ctx, ctx->buf, ctx->buf );

            dlen -= 16;
            p += 16;
            out_p += 16;
        }

        if( dlen > 0 )
        {
            gcm_incr( ctx->y );
            if( ( ret = gcm_mask( ctx, ectr, 0, dlen, p, out_p ) ) != ZMCRYPTO_ERR_SUCCESSED )
                { return ret; }
        }

        zmcrypto_memset(&ectr, 0, sizeof(ectr));
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror gcm_final (
        struct gcm_ctx* ctx,
        uint8_t *tag,
        uint32_t taglen
        )
    {
        uint8_t work_buf[16];
        uint32_t i;
        uint64_t orig_len;
        uint64_t orig_add_len;

        orig_len = ctx->len * 8;
        orig_add_len = ctx->add_len * 8;

        if ( ctx->len == 0 && ctx->add_len % 16 != 0 )
            { gcm_mult( ctx, ctx->buf, ctx->buf ); }

        if ( taglen > 16 || taglen < 4 )
            { return ZMCRYPTO_ERR_INVALID_TSIZE; }

        if( ctx->len % 16 != 0 )
            { gcm_mult( ctx, ctx->buf, ctx->buf ); }

        zmcrypto_memcpy( tag, ctx->base_ectr, taglen );

        if( orig_len || orig_add_len )
        {
            zmcrypto_memset( work_buf, 0x00, 16 );

            PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
            PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
            PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
            PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

            for( i = 0; i < 16; i++ )
                { ctx->buf[i] ^= work_buf[i]; }

            gcm_mult( ctx, ctx->buf, ctx->buf );

            for( i = 0; i < taglen; i++ )
                { tag[i] ^= ctx->buf[i]; }
        }
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif /* ZMCRYPTO_ALGO_GCM */
