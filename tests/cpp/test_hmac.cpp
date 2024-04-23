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
#include "test_hmac.h"

#if defined TEST_FOR_CRYPTOPP
    #define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/hmac.h"
    #include "include/md5.h"
    #include "include/sha.h"
    using namespace CryptoPP;
#endif

namespace{
    #if defined ZMCRYPTO_ALGO_MD5
        zmcrypto::sdk g_hmac_sdk;
        void*   _md5_new         (void) { return g_hmac_sdk.zm_md5_new(); }
        void    _md5_free        (void* ctx) { g_hmac_sdk.zm_md5_free((md5_ctx*)ctx); }
        int32_t _md5_digest_size (void) { return g_hmac_sdk.zm_md5_digest_size(); }
        int32_t _md5_block_size  (void) { return g_hmac_sdk.zm_md5_block_size();; }
        void    _md5_init        (void* ctx) { g_hmac_sdk.zm_md5_init((md5_ctx*)ctx); }
        void    _md5_starts      (void* ctx) { g_hmac_sdk.zm_md5_starts((md5_ctx*)ctx); }
        void    _md5_update      (void* ctx, uint8_t* data, uint32_t dlen) { g_hmac_sdk.zm_md5_update((md5_ctx*)ctx, data, dlen); }
        void    _md5_final       (void* ctx, uint8_t* output) { g_hmac_sdk.zm_md5_final((md5_ctx*)ctx, output); }
    #endif
    #if defined ZMCRYPTO_ALGO_SHA1
        void*   _sha1_new         (void) { return g_hmac_sdk.zm_sha1_new(); }
        void    _sha1_free        (void* ctx) { g_hmac_sdk.zm_sha1_free((sha1_ctx*)ctx); }
        int32_t _sha1_digest_size (void) { return g_hmac_sdk.zm_sha1_digest_size(); }
        int32_t _sha1_block_size  (void) { return g_hmac_sdk.zm_sha1_block_size();; }
        void    _sha1_init        (void* ctx) { g_hmac_sdk.zm_sha1_init((sha1_ctx*)ctx); }
        void    _sha1_starts      (void* ctx) { g_hmac_sdk.zm_sha1_starts((sha1_ctx*)ctx); }
        void    _sha1_update      (void* ctx, uint8_t* data, uint32_t dlen) { g_hmac_sdk.zm_sha1_update((sha1_ctx*)ctx, data, dlen); }
        void    _sha1_final       (void* ctx, uint8_t* output) { g_hmac_sdk.zm_sha1_final((sha1_ctx*)ctx, output); }
    #endif
}

void test_case_hmac(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "hmac.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, message, MAC, repeat, comment;
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
        if (!get_key_val_pair(test_vec, i, "message", message)){
            printf("get key-value pair failed: message\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "MAC", MAC)){
            printf("get key-value pair failed: MAC\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_HMAC && defined ZMCRYPTO_ALGO_SHA1 && defined ZMCRYPTO_ALGO_MD5
        {
            CONTEXT_TYPE_PTR(hmac) ctx = _sdk->zm_hmac_new ();
            int32_t digest_size = 0;

            if (algorithm == "hmac-md5"){
                _sdk->zm_hmac_init(ctx, _md5_new, _md5_free, _md5_digest_size, _md5_block_size, _md5_init, _md5_starts, _md5_update, _md5_final);
                digest_size = _md5_digest_size();
            }
            else if (algorithm == "hmac-sha1"){
                _sdk->zm_hmac_init(ctx, _sha1_new, _sha1_free, _sha1_digest_size, _sha1_block_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_final);
                digest_size = _sha1_digest_size();
            }
            else
            {
                printf ("algorithm not supports\n");
                _sdk->zm_hmac_free (ctx);
                return;
            }

            _sdk->zm_hmac_starts (ctx, (uint8_t*)key.c_str(), key.length());

            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            for (int j = 0; j < loop; j++){
                _sdk->zm_hmac_update (ctx, (uint8_t*)message.c_str(), message.length());
            }

            uint8_t* output = new uint8_t[digest_size];
            _sdk->zm_hmac_final (ctx, output);
            _sdk->zm_hmac_free (ctx);

            if (MAC == std::string((char*)output, digest_size)){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }
        #endif

        #if defined TEST_FOR_CRYPTOPP
        {
            HMAC_Base* HmacPtr = NULL;
            if (algorithm == "hmac-md5"){
                HmacPtr = new HMAC<Weak::MD5>;
            }
            else if (algorithm == "hmac-sha1"){
                HmacPtr = new HMAC<SHA1>;
            }
            else
            {
                printf ("algorithm not supports\n");
                return;
            }

            HmacPtr->SetKey((CryptoPP::byte*)(uint8_t*)key.c_str(), key.length());
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            for (int j = 0; j < loop; j++){
                HmacPtr->Update((uint8_t*)message.c_str(), message.length());
            }

            SecByteBlock digest(HmacPtr->DigestSize());
            HmacPtr->Final (digest);

            if (MAC == std::string((char*)(CryptoPP::byte *)digest, HmacPtr->DigestSize())){
                format_output("%s by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete HmacPtr;
            HmacPtr = NULL;
        }
        #endif
    }
}