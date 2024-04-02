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
#include "test_engine.h"
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

void* p1 =  NULL; 
void* p2 =  NULL; 
void* p3 =  NULL; 
void* p4 =  NULL; 
void* p5 =  NULL; 
void* p6 =  NULL; 
void* p7 =  NULL; 
void* p8 =  NULL; 
void* p9 =  NULL; 
void* p10 = NULL; 
void* p11 = NULL; 

void* f1 =  NULL; 
void* f2 =  NULL; 
void* f3 =  NULL; 
void* f4 =  NULL; 
void* f5 =  NULL; 
void* f6 =  NULL; 
void* f7 =  NULL; 
void* f8 =  NULL; 
void* f9 =  NULL; 
void* f10 = NULL; 
void* f11 = NULL; 

void test_case_hook_aes(zmcrypto::sdk* _sdk)
{
#if defined __linux__
    modulehandle = dlopen("/home/zhangluduo/data2t/zmcrypto_git/bin/engine.so", RTLD_LAZY);
#elif defined _WIN32
    modulehandle = LoadLibraryA("./engine.dll");
#endif

    if (!modulehandle){
        printf("load %s failed", "./engine.so");
        return;
    }

#if defined __linux__
    p1 =  dlsym(modulehandle, "hook_aes_block_size");
    p2 =  dlsym(modulehandle, "hook_aes_dec_block");
    p3 =  dlsym(modulehandle, "hook_aes_enc_block");
    p4 =  dlsym(modulehandle, "hook_aes_free");
    p5 =  dlsym(modulehandle, "hook_aes_init");
    p6 =  dlsym(modulehandle, "hook_aes_ksize_max");
    p7 =  dlsym(modulehandle, "hook_aes_ksize_min");
    p8 =  dlsym(modulehandle, "hook_aes_ksize_multiple");
    p9 =  dlsym(modulehandle, "hook_aes_new");
    p10 = dlsym(modulehandle, "hook_aes_set_dkey");
    p11 = dlsym(modulehandle, "hook_aes_set_ekey");
#elif defined _WIN32
    p1 =  GetProcAddress((HMODULE)modulehandle, "aes_block_size2");
    p2 =  GetProcAddress((HMODULE)modulehandle, "aes_dec_block2");
    p3 =  GetProcAddress((HMODULE)modulehandle, "aes_enc_block2");
    p4 =  GetProcAddress((HMODULE)modulehandle, "aes_free2");
    p5 =  GetProcAddress((HMODULE)modulehandle, "aes_init2");
    p6 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_max2");
    p7 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_min2");
    p8 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_multiple2");
    p9 =  GetProcAddress((HMODULE)modulehandle, "aes_new2");
    p10 = GetProcAddress((HMODULE)modulehandle, "aes_set_dkey2");
    p11 = GetProcAddress((HMODULE)modulehandle, "aes_set_ekey2");
#endif

    printf ("p1 : %p\n", p1 );
    printf ("p2 : %p\n", p2 );
    printf ("p3 : %p\n", p3 );
    printf ("p4 : %p\n", p4 );
    printf ("p5 : %p\n", p5 );
    printf ("p6 : %p\n", p6 );
    printf ("p7 : %p\n", p7 );
    printf ("p8 : %p\n", p8 );
    printf ("p9 : %p\n", p9 );
    printf ("p10: %p\n", p10);
    printf ("p11: %p\n", p11);

    f1 =  (void*)_sdk->zm_replace_fnc("zm_aes_block_size", p1 );
    f2 =  (void*)_sdk->zm_replace_fnc("zm_aes_dec_block", p2 );
    f3 =  (void*)_sdk->zm_replace_fnc("zm_aes_enc_block", p3 );
    f4 =  (void*)_sdk->zm_replace_fnc("zm_aes_free", p4 );
    f5 =  (void*)_sdk->zm_replace_fnc("zm_aes_init", p5 );
    f6 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_max", p6 );
    f7 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_min", p7 );
    f8 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_multiple", p8 );
    f9 =  (void*)_sdk->zm_replace_fnc("zm_aes_new", p9 );
    f10 = (void*)_sdk->zm_replace_fnc("zm_aes_set_dkey", p10);
    f11 = (void*)_sdk->zm_replace_fnc("zm_aes_set_ekey", p11);

    printf ("f1 : %p\n", f1 );
    printf ("f2 : %p\n", f2 );
    printf ("f3 : %p\n", f3 );
    printf ("f4 : %p\n", f4 );
    printf ("f5 : %p\n", f5 );
    printf ("f6 : %p\n", f6 );
    printf ("f7 : %p\n", f7 );
    printf ("f8 : %p\n", f8 );
    printf ("f9 : %p\n", f9 );
    printf ("f10: %p\n", f10);
    printf ("f11: %p\n", f11);
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf ("hook aes completed\n");
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

void test_case_unhook_aes(zmcrypto::sdk* _sdk){
    void* q1 =  (void*)_sdk->zm_replace_fnc("zm_aes_block_size", f1 );
    void* q2 =  (void*)_sdk->zm_replace_fnc("zm_aes_dec_block", f2 );
    void* q3 =  (void*)_sdk->zm_replace_fnc("zm_aes_enc_block", f3 );
    void* q4 =  (void*)_sdk->zm_replace_fnc("zm_aes_free", f4 );
    void* q5 =  (void*)_sdk->zm_replace_fnc("zm_aes_init", f5 );
    void* q6 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_max", f6 );
    void* q7 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_min", f7 );
    void* q8 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_multiple", f8 );
    void* q9 =  (void*)_sdk->zm_replace_fnc("zm_aes_new", f9 );
    void* q10 = (void*)_sdk->zm_replace_fnc("zm_aes_set_dkey", f10);
    void* q11 = (void*)_sdk->zm_replace_fnc("zm_aes_set_ekey", f11);

    printf ("q1 : %p\n", q1 );
    printf ("q2 : %p\n", q2 );
    printf ("q3 : %p\n", q3 );
    printf ("q4 : %p\n", q4 );
    printf ("q5 : %p\n", q5 );
    printf ("q6 : %p\n", q6 );
    printf ("q7 : %p\n", q7 );
    printf ("q8 : %p\n", q8 );
    printf ("q9 : %p\n", q9 );
    printf ("q10: %p\n", q10);
    printf ("q11: %p\n", q11);
#if defined __linux__
    dlclose(modulehandle);
#elif defined _WIN32
    FreeLibrary(modulehandle);
#endif
    modulehandle = NULL;
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf ("unhook aes completed\n");
    printf ("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}
