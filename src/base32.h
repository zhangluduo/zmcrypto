
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

#if !defined ZMCRYPTO_BASE32_H
#define ZMCRYPTO_BASE32_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_BASE32

        #define BASE32_RFC4648   (0 & 0xff) 
        #define BASE32_BASE32HEX (1 & 0xff) 
        #define BASE32_ZBASE32   (2 & 0xff) 
        #define BASE32_CROCKFORD (3 & 0xff) 

        /*
        options:
            The upper 32 bits are used to indicate how many characters are needed to wrap a line.
            The lower 32 bits indicate which encoding table to use.
            here are two coding tables here, 
            table[0] is "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            table[1] is "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            table[2] is "ybndrfg8ejkmcpqxot1uwisza345h769"
            table[3] is "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        */
        zmerror base32_encode(
            uint8_t *input, 
            uint32_t ilen, 
            uint8_t *output, 
            uint32_t *olen, 
            uint32_t options
        );

        zmerror base32_decode(
            uint8_t *input,  
            uint32_t ilen, 
            uint8_t *output, 
            uint32_t *olen, 
            uint32_t options
        );

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_BASE32_H */
