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

#include "debug.h"

#if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
    #if defined _WIN32
        /* TODO */
    #else
        #include <stdarg.h>
        void zmcrypto_log(char* file, char* fn, int ln, char* fmt, ...)
        {
            char* pstr = NULL;
            va_list args;
            va_start(args, fmt);

            (void)vasprintf(&pstr, fmt, args);
            va_end(args);
            zmcrypto_printf ("[%s:%d:%s] %s\n", file, ln, fn, pstr);
            free(pstr);
            pstr = NULL;
        }
    #endif
#endif /* ZMCRYPTO_DEBUG */
