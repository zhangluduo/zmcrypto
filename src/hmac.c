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
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

/*
HMAC(K, m) = H ((K' ⊕ opad) || H(K' ⊕ ipad) || m)

where 
    H is a cryptographic hash function, 
    K is the secret key, 
    m is the message to be authenticated, 
    K' is another secret key, derived from the original key K (by 
       padding K to the right with extra zeroes to the input block 
       size of the hash function, or by hashing K if it is longer 
       than that block size), || denotes concatenation, 
    ⊕  denotes exclusive or (XOR), opad is the outer padding (0x5c5c5c...
       5c5c, one-block-long hexadecimal constant), and ipad is the inner
       padding (0x363636...3636, one-block-long hexadecimal constant). 
*/

#include "hmac.h"

#if defined ZMCRYPTO_ALGO_HMAC

	struct hmac_ctx* hmac_new (void)
	{
        struct hmac_ctx* ctx = (struct hmac_ctx*)zmcrypto_malloc(sizeof(struct hmac_ctx));
        zmcrypto_memset(ctx, 0, sizeof(struct hmac_ctx));
        return ctx;
	}

	void hmac_free (struct hmac_ctx* ctx)
	{
		if (ctx)
		{
			if (ctx->hash_ctx)
			{
				ctx->hash_free(ctx->hash_ctx);
				ctx->hash_ctx = NULL;
			}
			zmcrypto_free(ctx);
			ctx = NULL;
		}
	}

	void hmac_init (struct hmac_ctx* ctx,
		void*   (*hash_new)         (void),
		void    (*hash_free)        (void* ctx),
		int32_t (*hash_digest_size) (void),
		int32_t (*hash_block_size)  (void),
		void    (*hash_init)        (void* ctx),
		void    (*hash_starts)      (void* ctx),
		void    (*hash_update)      (void* ctx, uint8_t* data, uint32_t dlen),
		void    (*hash_final)       (void* ctx, uint8_t* output)
	)
	{
		ctx->hash_ctx         = NULL            ;
		ctx->hash_new         = hash_new        ;
		ctx->hash_free        = hash_free       ;
		ctx->hash_digest_size = hash_digest_size;
		ctx->hash_block_size  = hash_block_size ;
		ctx->hash_init        = hash_init       ;
		ctx->hash_starts      = hash_starts     ;
		ctx->hash_update      = hash_update     ;
		ctx->hash_final       = hash_final      ;

		zmcrypto_memset(ctx->temp, 0, DIGEST_MAX_BLOCK_SIZE);
		zmcrypto_memset(ctx->ipad, 0, DIGEST_MAX_BLOCK_SIZE);
		zmcrypto_memset(ctx->opad, 0, DIGEST_MAX_BLOCK_SIZE);
	}

	void hmac_do_hash (struct hmac_ctx* ctx, uint8_t* data, uint32_t dlen, uint8_t* output)
	{
		void* hashctx = (void*)(ctx->hash_new());
		ctx->hash_init(hashctx);
		ctx->hash_starts(hashctx);
		ctx->hash_update(hashctx, data, dlen);
		ctx->hash_final(hashctx, output);
		ctx->hash_free(hashctx);
	}

	void hmac_reset (struct hmac_ctx* ctx)
	{
		ctx->hash_free(ctx->hash_ctx);
		ctx->hash_ctx = NULL; 

		zmcrypto_memset(ctx->temp, 0, DIGEST_MAX_BLOCK_SIZE);
		zmcrypto_memset(ctx->ipad, 0, DIGEST_MAX_BLOCK_SIZE);
		zmcrypto_memset(ctx->opad, 0, DIGEST_MAX_BLOCK_SIZE);
	}

	int32_t hmac_digest_size (struct hmac_ctx* ctx)
	{
		return ctx->hash_digest_size();
	}

	zmerror hmac_starts (struct hmac_ctx* ctx, uint8_t* key, uint32_t klen)
	{
		if (ctx->hash_ctx == NULL)
		{
			ctx->hash_ctx = ctx->hash_new();
		}  

		int32_t blocksize = ctx->hash_block_size();
		if (klen > (uint32_t)blocksize)
		{
			hmac_do_hash(ctx, key, klen, ctx->temp);
			key = ctx->temp;
			klen = ctx->hash_digest_size();
		}
    
		zmcrypto_memset(ctx->ipad, 0x36, blocksize);
		zmcrypto_memset(ctx->opad, 0x5C, blocksize);

		for(uint32_t i = 0; i < klen; i++ )
		{
			ctx->ipad[i] = ctx->ipad[i] ^ key[i];
			ctx->opad[i] = ctx->opad[i] ^ key[i];
		}

		ctx->hash_starts(ctx->hash_ctx);
		ctx->hash_update(ctx->hash_ctx, ctx->ipad, blocksize);
		return ZMCRYPTO_ERR_SUCCESSED;
	}

	void hmac_update (struct hmac_ctx* ctx, uint8_t* data, uint32_t dlen)
	{
		if (ctx->hash_update)
		{
			ctx->hash_update(ctx->hash_ctx, data, dlen);
		}
	}

	void hmac_final (struct hmac_ctx* ctx, uint8_t* output)
	{
		{
			ctx->hash_final(ctx->hash_ctx, ctx->temp);
			ctx->hash_free(ctx->hash_ctx);
			ctx->hash_ctx = NULL;
		}

		{
			int32_t blocksize = ctx->hash_block_size();
			int32_t digestsize = ctx->hash_digest_size();
			void* hashctx = (void*)(ctx->hash_new());
			ctx->hash_init(hashctx);
			ctx->hash_starts(hashctx);
			ctx->hash_update(hashctx, ctx->opad, blocksize);
			ctx->hash_update(hashctx, ctx->temp, digestsize);
			ctx->hash_final(hashctx, output);
			ctx->hash_free(hashctx);
		}
	}

#endif /* ZMCRYPTO_ALGO_HMAC */
