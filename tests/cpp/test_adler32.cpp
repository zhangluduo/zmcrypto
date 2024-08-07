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
#include "test_adler32.h"

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/adler32.h"
#endif

void test_info_adler32(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_ADLER32
    int32_t _size = _sdk->zm_adler32_checksum_size();
    printf("adler32 checksum size: %d\n", _size);
    #endif
}

void test_case_adler32(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "adler32.txt", test_vec)){
        printf("read test vector data failed [%s]\n", TEST_VECTOR_PATH "adler32.txt");
        return;
    }

	for (size_t i = 0; i < test_vec.size(); i++){

        std::string algorithm, message, checksum;
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }

        if (!get_key_val_pair(test_vec, i, "message", message)){
            printf("get key-value pair failed: message\n");
            return;
        }

        if (!get_key_val_pair(test_vec, i, "checksum", checksum)){
            printf("get key-value pair failed: checksum\n");
            return;
        }

        #if defined ZMCRYPTO_ALGO_ADLER32

            CONTEXT_TYPE_PTR(adler32) ctx = _sdk->zm_adler32_new();

            uint8_t* output = new uint8_t[_sdk->zm_adler32_checksum_size()];
            _sdk->zm_adler32_init (ctx);
            _sdk->zm_adler32_starts (ctx);
            _sdk->zm_adler32_update (ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            _sdk->zm_adler32_final (ctx, output);
            _sdk->zm_adler32_free (ctx);

            if (checksum == std::string((char*)output, _sdk->zm_adler32_checksum_size())){
                format_output("%s by ZmCrypto|passed\n", algorithm.c_str());
            }
            else{
                format_output("%s by ZmCrypto|failed\n", algorithm.c_str());
            }

            delete[] output;
            output = NULL;
        #endif

        #if defined TEST_FOR_CRYPTOPP
            CryptoPP::HashTransformation* HashPtr = new CryptoPP::Adler32();
            HashPtr->Update((const CryptoPP::byte *)(uint8_t*)message.c_str(), message.length());
            CryptoPP::SecByteBlock digest(HashPtr->DigestSize());
            HashPtr->Final (digest);

            if (checksum == std::string((char*)(CryptoPP::byte *)digest, HashPtr->DigestSize())){
                format_output("%s by Crypto++ |passed\n", algorithm.c_str());
            }
            else{
                format_output("%s by Crypto++|failed\n", algorithm.c_str());
            }

            delete HashPtr;
            HashPtr = NULL;
        #endif
    }
}

void test_speed_adler32(zmcrypto::sdk* _sdk)
{
        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;

    #if defined ZMCRYPTO_ALGO_ADLER32
    {
        CONTEXT_TYPE_PTR(adler32) ctx = _sdk->zm_adler32_new();
        uint8_t* output = new uint8_t[_sdk->zm_adler32_checksum_size()];
        _sdk->zm_adler32_init (ctx);
        _sdk->zm_adler32_starts (ctx);

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            _sdk->zm_adler32_update (ctx, (uint8_t*)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;

        format_output("adler32 by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        _sdk->zm_adler32_final (ctx, output);
        _sdk->zm_adler32_free (ctx);

        delete[] output;
        output = NULL;
    }
    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    {
        CryptoPP::HashTransformation* HashPtr = new CryptoPP::Adler32();
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

        format_output("adler32 by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        delete HashPtr;
        HashPtr = NULL;

        delete[] output;
        output = NULL;
    }
    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
    #endif
}