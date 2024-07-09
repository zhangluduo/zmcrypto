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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"
#include "vector_file.h"
#include "format_output.h"
#include "time_stamp.h"
#include "test_config.h"
#include "test_rc4.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/arc4.h"
#endif

void test_case_rc4(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "rc4.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, plaintext, ciphertext, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed: key\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed: plaintext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed: ciphertext\n");
            return;
        }

        #if defined ZMCRYPTO_ALGO_RC4
        /*Encrypt*/
        {
            uint8_t* output = new uint8_t[ciphertext.size()];

            zmerror err;
            CONTEXT_TYPE_PTR(rc4) ctx = _sdk->zm_rc4_new();
            _sdk->zm_rc4_init(ctx);
			err = _sdk->zm_rc4_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                delete[] output;
                output = NULL;
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_rc4_free (ctx);
                return;
            }
			_sdk->zm_rc4_encrypt(ctx, (uint8_t*)plaintext.c_str(), (uint32_t)plaintext.size(), output);
            _sdk->zm_rc4_free(ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] output;
            output = NULL;
        }
        /*Decrypt*/
        {
            uint8_t* output = new uint8_t[plaintext.size()];

            zmerror err;
            CONTEXT_TYPE_PTR(rc4) ctx = _sdk->zm_rc4_new();
            _sdk->zm_rc4_init(ctx);
			err = _sdk->zm_rc4_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                delete[] output;
                output = NULL;
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_rc4_free (ctx);
                return;
            }
			_sdk->zm_rc4_decrypt(ctx, (uint8_t*)ciphertext.c_str(), (uint32_t)ciphertext.size(), output);
            _sdk->zm_rc4_free(ctx);

            if (plaintext == std::string((char*)output, plaintext.length())){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] output;
            output = NULL;
        }
        
        #endif

        #if defined TEST_FOR_CRYPTOPP
        /*Encrypt*/
        {
            uint8_t* output = new uint8_t[ciphertext.size()];
            CryptoPP::Weak1::ARC4 arc4;
            arc4.SetKey ((uint8_t*)key.c_str(), key.size());
            arc4.ProcessData (output, (uint8_t*)plaintext.c_str(), plaintext.size());

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] output;
            output = NULL;
        }
        /*Decrypt*/
        {
            uint8_t* output = new uint8_t[ciphertext.size()];
            CryptoPP::Weak1::ARC4 arc4;
            arc4.SetKey ((uint8_t*)key.c_str(), key.size());
            arc4.ProcessData (output, (uint8_t*)ciphertext.c_str(), ciphertext.size());

            if (plaintext == std::string((char*)output, plaintext.length())){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] output;
            output = NULL;
        }
        #endif
    }
}

void test_info_rc4(zmcrypto::sdk* _sdk){
    int32_t min = _sdk->zm_rc4_ksize_min();
    int32_t max = _sdk->zm_rc4_ksize_max();
    int32_t mutiple = _sdk->zm_rc4_ksize_multiple();

    printf ("RC4 min key size: %d, max key size: %d, key size multiple: %d\n",
        min, max, mutiple);
}