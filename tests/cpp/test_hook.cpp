/*
 *  Copyright 2022 The ZmCrypto Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * 
 * Author: Zhang Luduo (zhangluduo@qq.com)
 *   Date: Nov. 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"
#include "vector_file.h"
#include "format_output.h"
#include "time_stamp.h"
#include "test_config.h"
#include "test_hook.h"
#include "test_md5.h"

#if defined __linux__
    #include <dlfcn.h>
    void* modulehandle = NULL;
#elif defined _WIN32
    #include <windows.h>
    HMODULE modulehandle = NULL;
#else
    #error unknown platform
#endif

    typedef zmerror (*pfn_hook_start)(void* module);
    typedef zmerror (*pfn_hook_finish)();

    pfn_hook_start _hook_start = NULL;
    pfn_hook_finish _hook_finish = NULL;

void test_case_hook_aes(zmcrypto::sdk* _sdk)
{
#if defined __linux__
    modulehandle = dlopen("/home/zhangluduo/data2t/zld/zmcrypto_git/bin/hook.so", RTLD_NOW);
#elif defined _WIN32
    modulehandle = LoadLibraryA("./hook.dll");
#endif

    if (!modulehandle){
#if defined __linux__
		printf("load %s failed (%s)\n", "hook.so", dlerror());
#elif defined _WIN32
		printf("load %s failed (code: %d)\n", "hook.so", GetLastError());
#endif
        return;
    }

#if defined __linux__
    _hook_start = (pfn_hook_start)dlsym(modulehandle, "hook_start");
    _hook_finish = (pfn_hook_finish)dlsym(modulehandle, "hook_finish");

#elif defined _WIN32
    _hook_start = (pfn_hook_start)GetProcAddress((HMODULE)modulehandle, "hook_start");
    _hook_finish = (pfn_hook_finish)GetProcAddress((HMODULE)modulehandle, "hook_finish");

#endif

    if (!_hook_start || !_hook_finish){
        goto fail;
    }

    if (_hook_start(_sdk->m_modulehandle) != ZMCRYPTO_ERR_SUCCESSED){
        goto fail;
    }

    goto succ;

fail:
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf ("hook aes failed\n");
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    return;
succ:
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf ("hook aes completed\n");
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    return;
}

void test_case_unhook_aes(zmcrypto::sdk* _sdk){

    if (!_hook_start || !_hook_finish){
        goto fail;
    }

    if (_hook_finish() != ZMCRYPTO_ERR_SUCCESSED){
        goto fail;
    }
    goto succ;

    fail:
        #if defined __linux__
            dlclose(modulehandle);
        #elif defined _WIN32
            FreeLibrary(modulehandle);
        #endif
            modulehandle = NULL;
            printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            printf ("unhook aes failed\n");
            printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        return;
    succ:

        #if defined __linux__
            dlclose(modulehandle);
        #elif defined _WIN32
            FreeLibrary(modulehandle);
        #endif
            modulehandle = NULL;
            printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            printf ("unhook aes completed\n");
            printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        return;
}
