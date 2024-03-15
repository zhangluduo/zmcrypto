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
#include "test_hmac.h"

#if defined TEST_FOR_CRYPTOPP
    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/hmac.h"
    #include "cryptopp820/include/md5.h"
    #include "cryptopp820/include/sha.h"
    #include "cryptopp820/include/sm3.h"
    #include "cryptopp820/include/pwdbased.h"
    using namespace CryptoPP;
#endif

namespace{
    zmcrypto::sdk g_pbkdf2_sdk;
    #if defined ZMCRYPTO_ALGO_MD5
        void*   _md5_new         (void) { return g_pbkdf2_sdk.zm_md5_new(); }
        void    _md5_free        (void* ctx) { g_pbkdf2_sdk.zm_md5_free((md5_ctx*)ctx); }
        int32_t _md5_digest_size (void) { return g_pbkdf2_sdk.zm_md5_digest_size(); }
        int32_t _md5_block_size  (void) { return g_pbkdf2_sdk.zm_md5_block_size();; }
        void    _md5_init        (void* ctx) { g_pbkdf2_sdk.zm_md5_init((md5_ctx*)ctx); }
        void    _md5_starts      (void* ctx) { g_pbkdf2_sdk.zm_md5_starts((md5_ctx*)ctx); }
        void    _md5_update      (void* ctx, uint8_t* data, uint32_t dlen) { g_pbkdf2_sdk.zm_md5_update((md5_ctx*)ctx, data, dlen); }
        void    _md5_final       (void* ctx, uint8_t* output) { g_pbkdf2_sdk.zm_md5_final((md5_ctx*)ctx, output); }
    #endif
    #if defined ZMCRYPTO_ALGO_SHA1
        void*   _sha1_new         (void) { return g_pbkdf2_sdk.zm_sha1_new(); }
        void    _sha1_free        (void* ctx) { g_pbkdf2_sdk.zm_sha1_free((sha1_ctx*)ctx); }
        int32_t _sha1_digest_size (void) { return g_pbkdf2_sdk.zm_sha1_digest_size(); }
        int32_t _sha1_block_size  (void) { return g_pbkdf2_sdk.zm_sha1_block_size();; }
        void    _sha1_init        (void* ctx) { g_pbkdf2_sdk.zm_sha1_init((sha1_ctx*)ctx); }
        void    _sha1_starts      (void* ctx) { g_pbkdf2_sdk.zm_sha1_starts((sha1_ctx*)ctx); }
        void    _sha1_update      (void* ctx, uint8_t* data, uint32_t dlen) { g_pbkdf2_sdk.zm_sha1_update((sha1_ctx*)ctx, data, dlen); }
        void    _sha1_final       (void* ctx, uint8_t* output) { g_pbkdf2_sdk.zm_sha1_final((sha1_ctx*)ctx, output); }
    #endif
    #if defined ZMCRYPTO_ALGO_SM3
        void*   _sm3_new         (void) { return g_pbkdf2_sdk.zm_sm3_new(); }
        void    _sm3_free        (void* ctx) { g_pbkdf2_sdk.zm_sm3_free((sm3_ctx*)ctx); }
        int32_t _sm3_digest_size (void) { return g_pbkdf2_sdk.zm_sm3_digest_size(); }
        int32_t _sm3_block_size  (void) { return g_pbkdf2_sdk.zm_sm3_block_size();; }
        void    _sm3_init        (void* ctx) { g_pbkdf2_sdk.zm_sm3_init((sm3_ctx*)ctx); }
        void    _sm3_starts      (void* ctx) { g_pbkdf2_sdk.zm_sm3_starts((sm3_ctx*)ctx); }
        void    _sm3_update      (void* ctx, uint8_t* data, uint32_t dlen) { g_pbkdf2_sdk.zm_sm3_update((sm3_ctx*)ctx, data, dlen); }
        void    _sm3_final       (void* ctx, uint8_t* output) { g_pbkdf2_sdk.zm_sm3_final((sm3_ctx*)ctx, output); }
    #endif
}

void test_case_pbkdf2(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "pbkdf2.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, password, salt, iterations, derived_key, derived_len, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "password", password)){
            printf("get key-value pair failed: password\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "salt", salt)){
            printf("get key-value pair failed: salt\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iterations", iterations)){
            printf("get key-value pair failed: iterations\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "derived-key", derived_key)){
            printf("get key-value pair failed: derived-key\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "derived-len", derived_len)){
            printf("get key-value pair failed: derived-len\n");
            return;
        }

        #if defined ZMCRYPTO_ALGO_PBKDF2 && defined ZMCRYPTO_ALGO_SHA1 && defined ZMCRYPTO_ALGO_MD5 && defined ZMCRYPTO_ALGO_SM3
        {
            uint8_t* dk2 = new uint8_t[atoi(derived_len.c_str())];

            if (algorithm == "pbkdf2-with-hmac-md5"){
                _sdk->zm_pbkdf2 (
                        _md5_new,_md5_free,_md5_digest_size,_md5_block_size,_md5_init,_md5_starts,_md5_update,_md5_final,
                        (uint8_t*)password.c_str(), password.length(), (uint8_t*)(salt.c_str()), salt.length(), atoi(iterations.c_str()), dk2, atoi(derived_len.c_str()));
            }
            else if (algorithm == "pbkdf2-with-hmac-sha1"){
                _sdk->zm_pbkdf2 (
                        _sha1_new,_sha1_free,_sha1_digest_size,_sha1_block_size,_sha1_init,_sha1_starts,_sha1_update,_sha1_final,
                        (uint8_t*)password.c_str(), password.length(), (uint8_t*)(salt.c_str()), salt.length(), atoi(iterations.c_str()), dk2, atoi(derived_len.c_str()));
            }
            else if (algorithm == "pbkdf2-with-hmac-sm3"){
                _sdk->zm_pbkdf2 (
                        _sm3_new,_sm3_free,_sm3_digest_size,_sm3_block_size,_sm3_init,_sm3_starts,_sm3_update,_sm3_final,
                        (uint8_t*)password.c_str(), password.length(), (uint8_t*)(salt.c_str()), salt.length(), atoi(iterations.c_str()), dk2, atoi(derived_len.c_str()));
            }
            else{
                printf ("algorithm not supports\n");
                delete[] dk2;
                dk2 = NULL;
                continue;;
            }

            if (atoi(derived_len.c_str()) == derived_key.length() && derived_key == std::string((char*)dk2, atoi(derived_len.c_str()))){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                for (int n = 0; n < derived_key.length(); n++){
                    printf ("%02x ", dk2[n]);
                }
                printf ("\n");
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] dk2;
            dk2 = NULL;
        }
        #endif

        #if defined TEST_FOR_CRYPTOPP

            if (algorithm == "pbkdf2-with-hmac-md5"){
                PKCS5_PBKDF2_HMAC < MD5 > pbkdf2;
                uint8_t* dk2 = new uint8_t[atoi(derived_len.c_str())];

                pbkdf2.DeriveKey(
                    dk2, 
                    atoi(derived_len.c_str()), 
                    0,
                    (const CryptoPP::byte*)(password.c_str()),
                    (size_t)(password.length()),
                    (const CryptoPP::byte*)(salt.c_str()),
                    (size_t)(salt.length()),
                    atoi(iterations.c_str()));

                if (atoi(derived_len.c_str()) == derived_key.length() && derived_key == std::string((char*)dk2, atoi(derived_len.c_str()))){
                    format_output("%s by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                delete[] dk2;
                dk2 = NULL;
            }
            else if (algorithm == "pbkdf2-with-hmac-sha1"){
                PKCS5_PBKDF2_HMAC < SHA1 > pbkdf2;
                uint8_t* dk2 = new uint8_t[atoi(derived_len.c_str())];

                pbkdf2.DeriveKey(
                    dk2, 
                    atoi(derived_len.c_str()), 
                    0,
                    (const CryptoPP::byte*)(password.c_str()),
                    (size_t)(password.length()),
                    (const CryptoPP::byte*)(salt.c_str()),
                    (size_t)(salt.length()),
                    atoi(iterations.c_str()));

                if (atoi(derived_len.c_str()) == derived_key.length() && derived_key == std::string((char*)dk2, atoi(derived_len.c_str()))){
                    format_output("%s by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                delete[] dk2;
                dk2 = NULL;
            }
            else if (algorithm == "pbkdf2-with-hmac-sm3"){
                PKCS5_PBKDF2_HMAC < SM3 > pbkdf2;
                uint8_t* dk2 = new uint8_t[atoi(derived_len.c_str())];

                pbkdf2.DeriveKey(
                    dk2, 
                    atoi(derived_len.c_str()), 
                    0,
                    (const CryptoPP::byte*)(password.c_str()),
                    (size_t)(password.length()),
                    (const CryptoPP::byte*)(salt.c_str()),
                    (size_t)(salt.length()),
                    atoi(iterations.c_str()));

                if (atoi(derived_len.c_str()) == derived_key.length() && derived_key == std::string((char*)dk2, atoi(derived_len.c_str()))){
                    format_output("%s by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                delete[] dk2;
                dk2 = NULL;
            }
            else{
                printf ("algorithm not supports\n");
                continue;;
            }


        #endif
    }
}