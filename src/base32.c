
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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "base32.h"

#if defined ZMCRYPTO_ALGO_BASE32

    zmerror base32_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        // const char *alphabet[4] = {
        //     "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",     /* id = BASE32_RFC4648   */
        //     "0123456789ABCDEFGHIJKLMNOPQRSTUV",     /* id = BASE32_BASE32HEX */
        //     "ybndrfg8ejkmcpqxot1uwisza345h769",     /* id = BASE32_ZBASE32   */
        //     "0123456789ABCDEFGHJKMNPQRSTVWXYZ"      /* id = BASE32_CROCKFORD */
        // };

        // uint16_t hi = (uint16_t)(options >> 16);         /* skip whitespace(0x0d, 0x0a, 0x20) */
        // uint16_t lo = (uint16_t)(options & 0x000000ff);  /* table index */

        // if (lo != 0 && lo != 1) { return ZMCRYPTO_ERR_OVERFLOW; }

        // uint32_t i, x;

        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror base32_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif