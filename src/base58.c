
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

#include "base58.h"

#if defined ZMCRYPTO_ALGO_BASE58

    zmerror base58_encode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

    zmerror base58_decode(uint8_t *input, uint32_t ilen, uint8_t *output, uint32_t *olen, uint32_t options)
    {
        return ZMCRYPTO_ERR_SUCCESSED;
    }

#endif