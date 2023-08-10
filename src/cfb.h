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

#if !defined ZMCRYPTO_CFB_H
#define ZMCRYPTO_CFB_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

#if defined ZMCRYPTO_ALGO_CFB

#if !defined MAX_IV_SIZE
#define MAX_IV_SIZE (256)
#endif

	struct cfb_ctx
	{
		void*   (*cipher_new)           (void);
		void(*cipher_free)              (void* ctx);
		void(*cipher_init)              (void* ctx);
		int32_t(*cipher_block_size)     (void);
		int32_t(*cipher_ksize_min)      (void);
		int32_t(*cipher_ksize_max)      (void);
		int32_t(*cipher_ksize_multiple) (void);
		int32_t(*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize);
		int32_t(*cipher_set_dkey)       (void* ctx, uint8_t* key, uint32_t ksize);
		void(*cipher_enc_block)         (void* ctx, uint8_t* plaintext, uint8_t* ciphertext);
		void(*cipher_dec_block)         (void* ctx, uint8_t* ciphertext, uint8_t* plaintext);

		void* cipher_ctx;
		uint32_t iv_offset;
		uint8_t iv[MAX_IV_SIZE];
		uint8_t temp[MAX_IV_SIZE];

		/*
		SP 800-38A
		6.3
		For performance considerations, the feedback size value uses the block size.
		*/
		/*
		uint32_t feedback_bits;
		*/
	} ;

	void cfb_init(
        struct cfb_ctx* ctx,
		void*   (*cipher_new)           (void),
		void(*cipher_free)              (void* ctx),
		void(*cipher_init)              (void* ctx),
		int32_t(*cipher_block_size)     (void),
		int32_t(*cipher_ksize_min)      (void),
		int32_t(*cipher_ksize_max)      (void),
		int32_t(*cipher_ksize_multiple) (void),
		int32_t(*cipher_set_ekey)       (void* ctx, uint8_t* key, uint32_t ksize),
		void(*cipher_enc_block)         (void* ctx, uint8_t* plaintext, uint8_t* ciphertext)
		);

	struct cfb_ctx* cfb_new(
		void
	);

	void cfb_free(
		struct cfb_ctx* ctx
	);

	zmerror cfb_set_ekey(
		struct cfb_ctx* ctx, 
		uint8_t* key, 
		uint32_t ksize, 
		uint8_t* iv, 
		uint32_t ivsize
	);

	zmerror cfb_set_dkey(
		struct cfb_ctx* ctx, 
		uint8_t* key, 
		uint32_t ksize, 
		uint8_t* iv, 
		uint32_t ivsize
	);

	zmerror cfb_enc(
		struct cfb_ctx* ctx, 
		uint8_t* input, 
		uint32_t ilen, 
		uint8_t* output
	);

	zmerror cfb_dec(
		struct cfb_ctx* ctx, 
		uint8_t* input, 
		uint32_t ilen, 
		uint8_t* output
	);

#endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_CFB_H */
