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
 *   Date: Aug. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */

#include "debug.h"
#include "zmconfig.h"

#if defined ZMCRYPTO_DEBUG && ZMCRYPTO_DEBUG == 1
    #if defined _WIN32
        #include <stdarg.h>
        void zmcrypto_log(char* file, char* fn, int ln, char* fmt, ...)
        {
            char* pstr = (char*)zmcrypto_malloc(4096);
			zmcrypto_memset(pstr, 0, 4096);
            va_list args;
            va_start(args, fmt);

            (void)vsprintf(pstr, fmt, args);
            va_end(args);
            zmcrypto_printf ("[%s:%d:%s] %s\n", file, ln, fn, pstr);
            zmcrypto_free(pstr);
            pstr = NULL;
        }
    #else
        #include <stdarg.h>
        void zmcrypto_log(char* file, char* fn, int ln, char* fmt, ...)
        {
            char* pstr = NULL;
            va_list args;
            va_start(args, fmt);

            (void)vasprintf(&pstr, (const char *)fmt, args);
            va_end(args);
            zmcrypto_printf ("[%s:%d:%s] %s\n", file, ln, fn, pstr);
            zmcrypto_free(pstr);
            pstr = NULL;
        }
    #endif
#endif /* ZMCRYPTO_DEBUG */
