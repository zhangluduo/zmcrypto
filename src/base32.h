
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
