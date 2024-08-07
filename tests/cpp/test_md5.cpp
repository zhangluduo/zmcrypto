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
#include "test_md5.h"

#if defined TEST_FOR_CRYPTOPP
    #define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/md5.h"
#endif

#if defined TEST_FOR_OPENSSL_SPEED
    #include <openssl/md5.h>
#endif

void test_info_md5(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_MD5
    int32_t _size = _sdk->zm_md5_digest_size();
    int32_t _size2 = _sdk->zm_md5_block_size();
    printf("md5 digest size: %d, block size: %d\n", _size, _size2);
    #endif
}


void test_case_md5(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "md5.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

	for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, message, digest, comment;
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

        #if defined ZMCRYPTO_ALGO_MD5

            CONTEXT_TYPE_PTR(md5) ctx = _sdk->zm_md5_new();
            uint8_t* output = new uint8_t[_sdk->zm_md5_digest_size()];
            _sdk->zm_md5_init (ctx);
            _sdk->zm_md5_starts (ctx);
			_sdk->zm_md5_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            _sdk->zm_md5_final (ctx, output);
            _sdk->zm_md5_free (ctx);
            if (digest == std::string((char*)output, _sdk->zm_md5_digest_size())){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        #endif

        #if defined TEST_FOR_CRYPTOPP
            CryptoPP::HashTransformation* HashPtr = new CryptoPP::Weak::MD5();
            HashPtr->Update((const CryptoPP::byte *)(uint8_t*)message.c_str(), message.length());
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
        #endif
    }
}

void test_speed_md5(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_MD5
        
        CONTEXT_TYPE_PTR(md5) ctx = _sdk->zm_md5_new();
        uint8_t* output = new uint8_t[_sdk->zm_md5_digest_size()];
        _sdk->zm_md5_init (ctx);
        _sdk->zm_md5_starts (ctx);

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            _sdk->zm_md5_update (ctx, (uint8_t*)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;
        format_output("md5 by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        _sdk->zm_md5_final (ctx, output);
        _sdk->zm_md5_free (ctx);

        delete[] output;
        output = NULL;
    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    {
        CryptoPP::HashTransformation* HashPtr = new CryptoPP::Weak::MD5();
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

        format_output("md5 by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        delete HashPtr;
        HashPtr = NULL;

        delete[] output;
        output = NULL;
    }
    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
    {
        MD5_CTX context;
        MD5_Init(&context);

        uint8_t* output = new uint8_t[16];

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            MD5_Update(&context, msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }

        MD5_Final(output, &context);

        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;

        format_output("md5 by OpenSSL|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        delete[] output;
        output = NULL;
    }
    #endif
}