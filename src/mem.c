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

/*
This MPI implementation is based on:
[BigNum Math: Implementing Cryptographic Multiple Precision Arithmetic]
Author: Tom St Denis
*/

#include "mem.h"

#if defined ZMCRYPTO_ALGO_MEM

    #error Some functions(malloc, free, memcpy, memset, ...) on specific platforms are not implemented here

    #if 0
    void* zm_malloc (size_t __size) 
    {
        return 0;
    }

    void* zm_realloc (void *__ptr, size_t __size) 
    {
        return 0;
    }

    void  zm_free (void *__ptr) 
    {

    }

    void* zm_memcpy (void *__restrict __dest, const void *__restrict __src, size_t __n) 
    {
        return 0;
    }

    int zm_memcmp (const void *__s1, const void *__s2, size_t __n) 
    {
        return 0;
    }

    void* zm_memset (void *__s, int __c, size_t __n) 
    {
        return 0;
    }
    #endif
    
#endif /* ZMCRYPTO_ALGO_MEM */
