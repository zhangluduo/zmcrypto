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

#include "ed2k.h"
#include "md4.h"

#if defined ZMCRYPTO_ALGO_ED2K

#define _ED2K_CHUNKSIZE 9728000 // (1024 * 9500)

    struct ed2k_ctx
    {
        struct md4_ctx* md4_ctx;
        struct md4_ctx* md4_ctx_final;
        uint32_t  buffer_size;
        uint8_t output[16];
        uint32_t  update_size;
        uint32_t  update_count;
    };

    struct ed2k_ctx* ed2k_new (void)
    {
        struct ed2k_ctx* ctx = (struct ed2k_ctx*)zmcrypto_malloc(sizeof(struct ed2k_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct ed2k_ctx));
        return ctx;
    }

    void ed2k_free (struct ed2k_ctx* ctx)
    {
        if (ctx->md4_ctx)
        {
            md4_free (ctx->md4_ctx);
            md4_free (ctx->md4_ctx_final);
            ctx->md4_ctx = NULL;
            ctx->md4_ctx_final = NULL;
        }
        zmcrypto_free(ctx);
    }

    int32_t ed2k_digest_size (void)
    { 
        return 16;
    }

    int32_t ed2k_block_size (void) 
    { 
        return 64; 
    }

    void ed2k_init (struct ed2k_ctx* ctx)
    { 
        zmcrypto_memset(ctx, 0, sizeof(struct ed2k_ctx)); 
    }

    void ed2k_starts (struct ed2k_ctx* ctx) 
    { 
        if (ctx->md4_ctx)
        {
            md4_free (ctx->md4_ctx);
            md4_free (ctx->md4_ctx_final);
            ctx->md4_ctx = NULL;
            ctx->md4_ctx_final = NULL;
        }

        ctx->md4_ctx = md4_new ();;
        ctx->md4_ctx_final = md4_new ();;

        md4_starts (ctx->md4_ctx);
        md4_starts (ctx->md4_ctx_final);
    }

    void ed2k_update (struct ed2k_ctx* ctx, uint8_t* data, uint32_t dsize)
    { 
        if (ctx->update_size + dsize >= _ED2K_CHUNKSIZE)
        {
            md4_update(ctx->md4_ctx, data, _ED2K_CHUNKSIZE - ctx->update_size);
            md4_final(ctx->md4_ctx, ctx->output);
            md4_starts(ctx->md4_ctx);
            md4_update(ctx->md4_ctx_final, ctx->output, 16);
            ctx->update_count++;

            int Offset = _ED2K_CHUNKSIZE - ctx->update_size;
            ctx->update_size = dsize - Offset;
            if (ctx->update_size)
                { md4_update(ctx->md4_ctx, data + Offset, ctx->update_size); }
        }
        else
        {
            md4_update(ctx->md4_ctx, data, dsize);
            ctx->update_size += dsize;
        }
    }

    void ed2k_final (struct ed2k_ctx* ctx, uint8_t output[16])
    {
        if (ctx->update_size)
            { md4_final(ctx->md4_ctx, ctx->output); }

        if (ctx->update_count >= 1)
        {    
            md4_update(ctx->md4_ctx_final, ctx->output, 16);
            md4_final(ctx->md4_ctx_final, output);
        }
        else
        {
            zmcrypto_memcpy(output, ctx->output, 16);
        }
    }

#endif /* ZMCRYPTO_ALGO_ED2K */
