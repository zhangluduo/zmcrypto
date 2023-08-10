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
 *   Date: Nov 2022
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
    #define GetProcAddress dlsym
#elif defined _WIN32
    #include <windows.h>
#endif


void output_aes(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat;
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed: key\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed: plaintext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed: ciphertext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_ECB && defined ZMCRYPTO_ALGO_AES

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "aes"){
            }else{
                continue;
            }

            CONTEXT_TYPE_PTR(aes) ctx = _sdk->zm_aes_new ();
            int32_t block_size = _sdk->zm_aes_block_size ();
            int32_t ksize_min = _sdk->zm_aes_ksize_min ();
            int32_t ksize_max = _sdk->zm_aes_ksize_max ();
            int32_t ksize_multiple = _sdk->zm_aes_ksize_multiple ();

            if (plaintext.length() != block_size || plaintext.length() != ciphertext.length())
            {
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                continue;
            }

            zmerror err = _sdk->zm_aes_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_aes_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            _sdk->zm_aes_enc_block (ctx, (uint8_t*) (plaintext.c_str()), output);
            _sdk->zm_aes_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|passed\n", algorithm.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|failed\n", algorithm.c_str());
            }

            delete[] output;
            output = NULL;
        }

        #endif
    }
}

void output_md5(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "md5.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    std::string algorithm, message, digest;
    if (!get_key_val_pair(test_vec, 0, "algorithm", algorithm)){
        printf("get key-value pair failed: algorithm\n");
        return;
    }
    if (!get_key_val_pair(test_vec, 0, "message", message)){
        printf("get key-value pair failed: message\n");
        return;
    }
    if (!get_key_val_pair(test_vec, 0, "digest", digest)){
        printf("get key-value pair failed: digest\n");
        return;
    }
    CONTEXT_TYPE_PTR(md5) ctx = _sdk->zm_md5_new();
    uint8_t* output = new uint8_t[_sdk->zm_md5_digest_size()];
    _sdk->zm_md5_init (ctx);
    _sdk->zm_md5_starts (ctx);
    _sdk->zm_md5_update (ctx, (uint8_t*)message.c_str(), message.length());
    _sdk->zm_md5_final (ctx, output);
    _sdk->zm_md5_free (ctx);

    if (digest == std::string((char*)output, _sdk->zm_md5_digest_size())){
        format_output("%s by ZmCrypto|passed\n", algorithm.c_str());
    }
    else{
        format_output("%s by ZmCrypto|failed\n", algorithm.c_str());
    }

    delete[] output;
    output = NULL;
}

void test_case_engine_aes(zmcrypto::sdk* _sdk)
{
#if defined __linux__
    void* modulehandle = dlopen("./libzmengine.so", RTLD_LAZY);
#elif defined _WIN32
    HMODULE modulehandle = LoadLibraryA("./zmengine.dll");
#endif

    if (!modulehandle){
        printf("load %s failed", "./libzmengine.so");
        return;
    }

    output_aes(_sdk);

#if defined __linux__
    void* p1 =  dlsym(modulehandle, "aes_block_size");
    void* p2 =  dlsym(modulehandle, "aes_dec_block");
    void* p3 =  dlsym(modulehandle, "aes_enc_block");
    void* p4 =  dlsym(modulehandle, "aes_free");
    void* p5 =  dlsym(modulehandle, "aes_init");
    void* p6 =  dlsym(modulehandle, "aes_ksize_max");
    void* p7 =  dlsym(modulehandle, "aes_ksize_min");
    void* p8 =  dlsym(modulehandle, "aes_ksize_multiple");
    void* p9 =  dlsym(modulehandle, "aes_new");
    void* p10 = dlsym(modulehandle, "aes_set_dkey");
    void* p11 = dlsym(modulehandle, "aes_set_ekey");
#elif defined _WIN32
    void* p1 =  GetProcAddress((HMODULE)modulehandle, "aes_block_size");
    void* p2 =  GetProcAddress((HMODULE)modulehandle, "aes_dec_block");
    void* p3 =  GetProcAddress((HMODULE)modulehandle, "aes_enc_block");
    void* p4 =  GetProcAddress((HMODULE)modulehandle, "aes_free");
    void* p5 =  GetProcAddress((HMODULE)modulehandle, "aes_init");
    void* p6 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_max");
    void* p7 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_min");
    void* p8 =  GetProcAddress((HMODULE)modulehandle, "aes_ksize_multiple");
    void* p9 =  GetProcAddress((HMODULE)modulehandle, "aes_new");
    void* p10 = GetProcAddress((HMODULE)modulehandle, "aes_set_dkey");
    void* p11 = GetProcAddress((HMODULE)modulehandle, "aes_set_ekey");
#endif

    void* f1 =  (void*)_sdk->zm_replace_fnc("zm_aes_block_size", p1 );
    void* f2 =  (void*)_sdk->zm_replace_fnc("zm_aes_dec_block", p2 );
    void* f3 =  (void*)_sdk->zm_replace_fnc("zm_aes_enc_block", p3 );
    void* f4 =  (void*)_sdk->zm_replace_fnc("zm_aes_free", p4 );
    void* f5 =  (void*)_sdk->zm_replace_fnc("zm_aes_init", p5 );
    void* f6 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_max", p6 );
    void* f7 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_min", p7 );
    void* f8 =  (void*)_sdk->zm_replace_fnc("zm_aes_ksize_multiple", p8 );
    void* f9 =  (void*)_sdk->zm_replace_fnc("zm_aes_new", p9 );
    void* f10 = (void*)_sdk->zm_replace_fnc("zm_aes_set_dkey", p10);
    void* f11 = (void*)_sdk->zm_replace_fnc("zm_aes_set_ekey", p11);

    output_aes(_sdk);

    _sdk->zm_replace_fnc("zm_aes_block_size", f1 );
    _sdk->zm_replace_fnc("zm_aes_dec_block", f2 );
    _sdk->zm_replace_fnc("zm_aes_enc_block", f3 );
    _sdk->zm_replace_fnc("zm_aes_free", f4 );
    _sdk->zm_replace_fnc("zm_aes_init", f5 );
    _sdk->zm_replace_fnc("zm_aes_ksize_max", f6 );
    _sdk->zm_replace_fnc("zm_aes_ksize_min", f7 );
    _sdk->zm_replace_fnc("zm_aes_ksize_multiple", f8 );
    _sdk->zm_replace_fnc("zm_aes_new", f9 );
    _sdk->zm_replace_fnc("zm_aes_set_dkey", f10);
    _sdk->zm_replace_fnc("zm_aes_set_ekey", f11);

#if defined __linux__
    dlclose(modulehandle);
#elif defined _WIN32
    FreeLibrary(modulehandle);
#endif
    
    modulehandle = NULL;
}

void test_case_engine_md5(zmcrypto::sdk* _sdk)
{
#if defined __linux__
    void* modulehandle = dlopen("./libzmengine.so", RTLD_LAZY);
#elif defined _WIN32
    HMODULE modulehandle = LoadLibraryA("./zmengine.dll");
#endif

    if (!modulehandle){
        printf("load %s failed", "./libzmengine.so");
        return;
    }

    output_md5(_sdk);

#if defined __linux__
    void* p1 =  dlsym(modulehandle, "md5_new");
    void* p2 =  dlsym(modulehandle, "md5_free");
    void* p3 =  dlsym(modulehandle, "md5_digest_size");
    void* p4 =  dlsym(modulehandle, "md5_block_size");
    void* p5 =  dlsym(modulehandle, "md5_init");
    void* p6 =  dlsym(modulehandle, "md5_starts");
    void* p7 =  dlsym(modulehandle, "md5_update");
    void* p8 =  dlsym(modulehandle, "md5_final");
#elif defined _WIN32
    void* p1 =  GetProcAddress((HMODULE)modulehandle, "md5_new");
    void* p2 =  GetProcAddress((HMODULE)modulehandle, "md5_free");
    void* p3 =  GetProcAddress((HMODULE)modulehandle, "md5_digest_size");
    void* p4 =  GetProcAddress((HMODULE)modulehandle, "md5_block_size");
    void* p5 =  GetProcAddress((HMODULE)modulehandle, "md5_init");
    void* p6 =  GetProcAddress((HMODULE)modulehandle, "md5_starts");
    void* p7 =  GetProcAddress((HMODULE)modulehandle, "md5_update");
    void* p8 =  GetProcAddress((HMODULE)modulehandle, "md5_final");
#endif

    void* f1 =  (void*)_sdk->zm_replace_fnc("zm_md5_new", p1 );
    void* f2 =  (void*)_sdk->zm_replace_fnc("zm_md5_free", p2 );
    void* f3 =  (void*)_sdk->zm_replace_fnc("zm_md5_digest_size", p3 );
    void* f4 =  (void*)_sdk->zm_replace_fnc("zm_md5_block_size", p4 );
    void* f5 =  (void*)_sdk->zm_replace_fnc("zm_md5_init", p5 );
    void* f6 =  (void*)_sdk->zm_replace_fnc("zm_md5_starts", p6 );
    void* f7 =  (void*)_sdk->zm_replace_fnc("zm_md5_update", p7 );
    void* f8 =  (void*)_sdk->zm_replace_fnc("zm_md5_final", p8 );

    output_md5(_sdk);

    _sdk->zm_replace_fnc("zm_md5_new", f1 );
    _sdk->zm_replace_fnc("zm_md5_free", f2 );
    _sdk->zm_replace_fnc("zm_md5_digest_size", f3 );
    _sdk->zm_replace_fnc("zm_md5_block_size", f4 );
    _sdk->zm_replace_fnc("zm_md5_init", f5 );
    _sdk->zm_replace_fnc("zm_md5_starts", f6 );
    _sdk->zm_replace_fnc("zm_md5_update", f7 );
    _sdk->zm_replace_fnc("zm_md5_final", f8 );

#if defined __linux__
    dlclose(modulehandle);
#elif defined _WIN32
    FreeLibrary(modulehandle);
#endif
    modulehandle = NULL;
}