
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
 *   Date: Aug 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#if !defined ZMCRYPTO_DEBUG_H
#define ZMCRYPTO_DEBUG_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
        #define ZMCRYPTO_LOG(...) zmcrypto_log(__FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);
        void zmcrypto_log(char* file, char* fn, int ln, char* fmt, ...);
    #else
        #define ZMCRYPTO_LOG(...)
    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_DEBUG */
