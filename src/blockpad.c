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

#include "blockpad.h"

#if defined ZMCRYPTO_ALGO_BLOCKPAD

	zmerror blockpad_zero(uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		if (dlen >= blen){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		zmcrypto_memset(block, 0, blen);
		zmcrypto_memcpy(block, data, dlen);
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockpad_iso10126(uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen, 
      void (*rng_get_bytes) (uint8_t* data, uint32_t dlen)) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		if (dlen >= blen){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		rng_get_bytes(block, blen);
		zmcrypto_memcpy(block, data, dlen);
		block[blen - 1] = blen - dlen;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockpad_ansix923(uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		if (dlen >= blen){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		zmcrypto_memset(block, 0, blen);
		zmcrypto_memcpy(block, data, dlen);
		block[blen - 1] = blen - dlen;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockpad_pkcs7(uint8_t* data, uint32_t dlen, uint8_t* block, uint32_t blen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		if (dlen >= blen){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		zmcrypto_memset(block, blen - dlen, blen);
		zmcrypto_memcpy(block, data, dlen);
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockdepad_zero(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		uint32_t zcount = 0;
		for (uint32_t i = blen - 1; i >= 0; i--){
			if (block[i] != 0){
			break;
			}
			zcount++;
		}

		if (blen - zcount > (*dlen)){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		zmcrypto_memcpy(data, block, blen - zcount);
		*dlen = blen - zcount;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockdepad_iso10126(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		uint32_t remove = block[blen - 1];

		if (((int32_t)(blen - remove)) < 0 || blen - remove > (*dlen)){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		zmcrypto_memcpy(data, block, blen - remove);
		*dlen = blen - remove;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockdepad_ansix923(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen) 
	{
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		uint32_t remove = block[blen - 1];

		if (((int32_t)(blen - remove)) < 0 || blen - remove > (*dlen)){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		for (uint32_t i = 0; i < remove - 1; i++){
			if ((block + (blen - remove))[i] != 0){
				return ZMCRYPTO_ERR_INVALID_PAD;
			}
		}

		zmcrypto_memcpy(data, block, blen - remove);
		*dlen = blen - remove;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

	zmerror blockdepad_pkcs7(uint8_t* block, uint32_t blen, uint8_t* data, uint32_t* dlen) 
	{ 
		if (blen % 8 != 0){
			return ZMCRYPTO_ERR_INVALID_BSIZE;
		}

		uint32_t remove = block[blen - 1];

		if (((int32_t)(blen - remove)) < 0 || blen - remove > (*dlen)){
			return ZMCRYPTO_ERR_INVALID_DSIZE;
		}

		for (uint32_t i = 0; i < remove - 1; i++){
			if ((block + (blen - remove))[i] != remove){
				return ZMCRYPTO_ERR_INVALID_PAD;
			}
		}

		zmcrypto_memcpy(data, block, blen - remove);
		*dlen = blen - remove;
		return ZMCRYPTO_ERR_SUCCESSED; 
	}

#endif /* ZMCRYPTO_ALGO_BLOCKPAD */
