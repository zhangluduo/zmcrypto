
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

#if !defined ZMCRYPTO_BLOCKPAD_H
#define ZMCRYPTO_BLOCKPAD_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_BLOCKPAD

		/*
		Most plain text messages do not consist of a number of bytes that completely fill blocks. 
		Often, there are not enough bytes to fill the last block. When this happens, a padding 
		string is added to the text. For example, if the block length is 64 bits and the last 
		block contains only 40 bits, 24 bits of padding are added.
		Some encryption standards specify a particular padding scheme. The following example 
		shows how these modes work. Given a blocklength of 8, a data length of 9, the number 
		of padding octets equal to 7, and the data equal to FF FF FF FF FF FF FF FF FF:
		Data: FF FF FF FF FF FF FF FF FF
		X923 padding: FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 07
		PKCS7 padding: FF FF FF FF FF FF FF FF FF 07 07 07 07 07 07 07
		ISO10126 padding: FF FF FF FF FF FF FF FF FF 7D 2A 75 EF F8 EF 07
		*/
		
		/*
		data	   [in] The data to pad
		dlen	   [in] The size of the data before padding
		block      [out] The new data block after padding
		blen       [in] Reference block size for 'block'
		*/
		zmerror blockpad_zero (
            uint8_t* data, 
            uint32_t dlen, 
            uint8_t* block,
            uint32_t blen
        );

		zmerror blockpad_iso10126 (
            uint8_t* data, 
            uint32_t dlen, 
            uint8_t* block, 
            uint32_t blen, 
            void (*rng_get_bytes) (uint8_t* data, uint32_t dlen)
        );

		zmerror blockpad_ansix923 (
            uint8_t* data, 
            uint32_t dlen, 
            uint8_t* block, 
            uint32_t blen
        );

		zmerror blockpad_pkcs7 (
            uint8_t* data, 
            uint32_t dlen, 
            uint8_t* block, 
            uint32_t blen
        );

		/*
		block      [in] The data block after remove padding
		blen       [in] Reference block size for 'block'
		data	   [in] The data to depad
		dlen	   [in/out] The size of the data before/after remove padding
		*/
		zmerror blockdepad_zero(
            uint8_t* block, 
            uint32_t blen, 
            uint8_t* data, 
            uint32_t* dlen
        );

		zmerror blockdepad_iso10126
            (uint8_t* block, 
            uint32_t blen, 
            uint8_t* data, 
            uint32_t* dlen
        );

		zmerror blockdepad_ansix923(
            uint8_t* block, 
            uint32_t blen, 
            uint8_t* data, 
            uint32_t* dlen
        );

		zmerror blockdepad_pkcs7(
            uint8_t* block, 
            uint32_t blen, 
            uint8_t* data, 
            uint32_t* dlen
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_BLOCKPAD_H */
