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

#if !defined ZMCRYPTO_MEM_H
#define ZMCRYPTO_MEM_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined ZMCRYPTO_ALGO_MEM

        void* zm_malloc (size_t __size);
        void* zm_realloc (void *__ptr, size_t __size);
        void  zm_free (void *__ptr);
        void* zm_memcpy (void *__restrict __dest, const void *__restrict __src, size_t __n);
        int   zm_memcmp (const void *__s1, const void *__s2, size_t __n);
        void* zm_memset (void *__s, int __c, size_t __n);

    #endif

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_MEM_H */
