
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

#if !defined ZMCRYPTO_BASE64_H
#define ZMCRYPTO_BASE64_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_BASE64

        /*
        options:
            The upper 32 bits are used to indicate how many characters are needed to wrap a line.
            The lower 32 bits indicate which encoding table to use.
            here are two coding tables here, 
            table[0] is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            table[1] is "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        */
       
        zmerror base64_encode(
            uint8_t *input, 
            uint32_t ilen, 
            uint8_t *output, 
            uint32_t *olen, 
            uint32_t options
        );

        zmerror base64_decode(
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

#endif /* ZMCRYPTO_BASE64_H */
