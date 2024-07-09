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
#include "test_sha1.h"

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/sha.h"
#endif

#if defined TEST_FOR_OPENSSL_SPEED
    #include <openssl/sha.h>
#endif

void test_info_sha1(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_SHA1
    int32_t _size = _sdk->zm_sha1_digest_size();
    int32_t _size2 = _sdk->zm_sha1_block_size();
    printf("sha1 digest size: %d, block size: %d\n", _size, _size2);
    #endif
}


void test_case_sha1(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "sha1.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_SHA1
        {
            CONTEXT_TYPE_PTR(sha1) ctx = _sdk->zm_sha1_new();
            uint8_t* output = new uint8_t[_sdk->zm_sha1_digest_size()];

            _sdk->zm_sha1_init (ctx);
            _sdk->zm_sha1_starts (ctx);

            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_sha1_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }
            _sdk->zm_sha1_final (ctx, output);
            _sdk->zm_sha1_free (ctx);

            if (digest == std::string((char*)output, _sdk->zm_sha1_digest_size())){
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
            CryptoPP::HashTransformation* HashPtr = new CryptoPP::SHA1();
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

void test_speed_sha1(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_SHA1
        CONTEXT_TYPE_PTR(sha1) ctx = _sdk->zm_sha1_new();
        uint8_t* output = new uint8_t[_sdk->zm_sha1_digest_size()];
        _sdk->zm_sha1_init (ctx);
        _sdk->zm_sha1_starts (ctx);

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            _sdk->zm_sha1_update (ctx, (uint8_t*)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;
        format_output("sha1 by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        _sdk->zm_sha1_final (ctx, output);
        _sdk->zm_sha1_free (ctx);

        delete[] output;
        output = NULL;
    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    {
        CryptoPP::HashTransformation* HashPtr = new CryptoPP::SHA1();
        uint8_t* output = new uint8_t[4];

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            HashPtr->Update((const CryptoPP::byte *)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;

        format_output("sha1 by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        delete HashPtr;
        HashPtr = NULL;

        delete[] output;
        output = NULL;
    }
    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
    {
        SHA_CTX context;
        SHA1_Init(&context);

        uint8_t* output = new uint8_t[20];

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            SHA1_Update(&context, msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }

        SHA1_Final(output, &context);

        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;

        format_output("sha1 by OpenSSL|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        delete[] output;
        output = NULL;
    }
    #endif
}