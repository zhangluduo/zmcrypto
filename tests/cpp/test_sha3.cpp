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
#include "test_sha3.h"

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/sha3.h"
#endif

#if defined TEST_FOR_OPENSSL_SPEED
    #include <openssl/evp.h>
#endif

void test_info_sha3(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_SHA3
    {
        int32_t _size = _sdk->zm_sha3_224_digest_size();
        int32_t _size2 = _sdk->zm_sha3_224_block_size();
        printf("sha3-224 digest size: %d, block size: %d\n", _size, _size2);
    }
    {
        int32_t _size = _sdk->zm_sha3_256_digest_size();
        int32_t _size2 = _sdk->zm_sha3_256_block_size();
        printf("sha3-256 digest size: %d, block size: %d\n", _size, _size2);
    }
    {
        int32_t _size = _sdk->zm_sha3_384_digest_size();
        int32_t _size2 = _sdk->zm_sha3_384_block_size();
        printf("sha3-384 digest size: %d, block size: %d\n", _size, _size2);
    }
    {
        int32_t _size = _sdk->zm_sha3_512_digest_size();
        int32_t _size2 = _sdk->zm_sha3_512_block_size();
        printf("sha3-512 digest size: %d, block size: %d\n", _size, _size2);
    }
    #endif
}


void test_case_sha3(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "sha3.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }
    
	for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, message, digest, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "message", message)){
            printf("get key-value pair failed: message\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "digest", digest)){
            printf("get key-value pair failed: digest\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        uint32_t loop = 1;
        if (!repeat.empty()){
            loop = atoi(repeat.c_str());
        }

        #if defined ZMCRYPTO_ALGO_SHA3
        if (algorithm == "sha3-224")
        {
            CONTEXT_TYPE_PTR(sha3_224) ctx = _sdk->zm_sha3_224_new();
            uint8_t* output = new uint8_t[_sdk->zm_sha3_224_digest_size()];

            _sdk->zm_sha3_224_init (ctx);
            _sdk->zm_sha3_224_starts (ctx);

            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_sha3_224_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }
            _sdk->zm_sha3_224_final (ctx, output);
            _sdk->zm_sha3_224_free (ctx);

            if (digest == std::string((char*)output, _sdk->zm_sha3_224_digest_size())){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }
        else if (algorithm == "sha3-256")
        {
            CONTEXT_TYPE_PTR(sha3_256) ctx = _sdk->zm_sha3_256_new();
            uint8_t* output = new uint8_t[_sdk->zm_sha3_256_digest_size()];

            _sdk->zm_sha3_256_init (ctx);
            _sdk->zm_sha3_256_starts (ctx);

            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_sha3_256_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }
            _sdk->zm_sha3_256_final (ctx, output);
            _sdk->zm_sha3_256_free (ctx);

            if (digest == std::string((char*)output, _sdk->zm_sha3_256_digest_size())){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }
        else if (algorithm == "sha3-384")
        {
            CONTEXT_TYPE_PTR(sha3_384) ctx = _sdk->zm_sha3_384_new();
            uint8_t* output = new uint8_t[_sdk->zm_sha3_384_digest_size()];

            _sdk->zm_sha3_384_init (ctx);
            _sdk->zm_sha3_384_starts (ctx);

            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_sha3_384_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }
            _sdk->zm_sha3_384_final (ctx, output);
            _sdk->zm_sha3_384_free (ctx);

            if (digest == std::string((char*)output, _sdk->zm_sha3_384_digest_size())){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }
        else if (algorithm == "sha3-512")
        {
            CONTEXT_TYPE_PTR(sha3_512) ctx = _sdk->zm_sha3_512_new();
            uint8_t* output = new uint8_t[_sdk->zm_sha3_512_digest_size()];

            _sdk->zm_sha3_512_init (ctx);
            _sdk->zm_sha3_512_starts (ctx);

            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_sha3_512_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }
            _sdk->zm_sha3_512_final (ctx, output);
            _sdk->zm_sha3_512_free (ctx);

            if (digest == std::string((char*)output, _sdk->zm_sha3_512_digest_size())){
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
            CryptoPP::HashTransformation* HashPtr = NULL;
            if (algorithm == "sha3-224"){
                HashPtr = new CryptoPP::SHA3_224();
            }
            else if (algorithm == "sha3-256"){
                HashPtr = new CryptoPP::SHA3_256();
            }
            else if (algorithm == "sha3-384"){
                HashPtr = new CryptoPP::SHA3_384();
            }
            else if (algorithm == "sha3-512"){
                HashPtr = new CryptoPP::SHA3_512();
            }
            for (uint32_t i = 0; i < loop;i ++){
                HashPtr->Update((const CryptoPP::byte *)(uint8_t*)message.c_str(), message.length());
            }
            CryptoPP::SecByteBlock output2(HashPtr->DigestSize());
            HashPtr->Final (output2);

            if (digest == std::string((char*)(CryptoPP::byte *)output2, HashPtr->DigestSize())){
                format_output("%s by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete HashPtr;
            HashPtr = NULL;
        }
        #endif
    }
}

void test_speed_sha3(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_SHA3
    #define zm_shaxxx(name)\
    {\
        CONTEXT_TYPE_PTR(name) ctx = _sdk->zm_ ##name## _new();\
        uint8_t* output = new uint8_t[_sdk->zm_ ##name## _digest_size()];\
        _sdk->zm_ ##name## _init (ctx);\
        _sdk->zm_ ##name## _starts (ctx);\
\
        uint8_t msg[16] = { 0 };\
        uint32_t mlen = 16;\
        uint64_t start = get_timestamp_us();\
        uint64_t end = 0;\
        uint64_t dsize = 0;\
        while (true)\
        {\
            _sdk->zm_ ##name## _update (ctx, (uint8_t*)msg, mlen);\
            dsize += mlen;\
            end = get_timestamp_us();\
            if (end - start >= TEST_TOTAL_SEC * 1000000)\
                break;\
        }\
        uint32_t elapsed = (uint32_t)(end - start);\
        double rate = (double)dsize / (double)elapsed;\
        format_output(#name " by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());\
\
        _sdk->zm_ ##name## _final (ctx, output);\
        _sdk->zm_ ##name## _free (ctx);\
\
        delete[] output;\
        output = NULL;\
    }\

    zm_shaxxx(sha3_224);
    zm_shaxxx(sha3_256);
    zm_shaxxx(sha3_384);
    zm_shaxxx(sha3_512);

    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    #define SHA3XXX(name)\
    {\
        CryptoPP::HashTransformation* HashPtr = new CryptoPP:: name ();\
\
        uint8_t* output = new uint8_t[64];\
\
        uint8_t msg[16] = { 0 };\
        uint32_t mlen = 16;\
        uint64_t start = get_timestamp_us();\
        uint64_t end = 0;\
        uint64_t dsize = 0;\
        while (true)\
        {\
            HashPtr->Update((const CryptoPP::byte *)msg, mlen);\
            dsize += mlen;\
            end = get_timestamp_us();\
            if (end - start >= TEST_TOTAL_SEC * 1000000)\
                break;\
        }\
        uint32_t elapsed = (uint32_t)(end - start);\
        double rate = (double)dsize / (double)elapsed;\
\
        format_output(#name " by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());\
\
        delete HashPtr;\
        HashPtr = NULL;\
\
        delete[] output;\
        output = NULL;\
    }\

    SHA3XXX(SHA3_224);
    SHA3XXX(SHA3_256);
    SHA3XXX(SHA3_384);
    SHA3XXX(SHA3_512);

    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
#define EVP_SHA3XXX(obj, name, len)\
    {\
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();\
        const EVP_MD *digest = obj();\
        EVP_DigestInit(mdctx, digest);\
\
        uint8_t* output = new uint8_t[len];\
        uint32_t olen = len;\
\
        uint8_t msg[16] = { 0 };\
        uint32_t mlen = 16;\
        uint64_t start = get_timestamp_us();\
        uint64_t end = 0;\
        uint64_t dsize = 0;\
        while (true)\
        {\
            (void)EVP_DigestUpdate(mdctx, msg, mlen);\
            dsize += mlen;\
            end = get_timestamp_us();\
            if (end - start >= TEST_TOTAL_SEC * 1000000)\
                break;\
        }\
\
        (void)EVP_DigestFinal_ex(mdctx, output, &olen);\
\
        uint32_t elapsed = (uint32_t)(end - start);\
        double rate = (double)dsize / (double)elapsed;\
\
        format_output(#name " by OpenSSL|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());\
\
        delete[] output;\
        output = NULL;\
\
        EVP_MD_CTX_destroy(mdctx);\
    }

    EVP_SHA3XXX(EVP_sha3_224, sha3_224, 224/8)
    EVP_SHA3XXX(EVP_sha3_256, sha3_256, 256/8)
    EVP_SHA3XXX(EVP_sha3_384, sha3_384, 384/8)
    EVP_SHA3XXX(EVP_sha3_512, sha3_512, 512/8)

    #endif
}