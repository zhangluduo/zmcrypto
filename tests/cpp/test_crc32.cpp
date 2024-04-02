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
#include "test_crc32.h"

#if defined TEST_FOR_CRYPTOPP
    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/crc.h"
#endif

void test_info_crc32(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_CRC32
    int32_t _size = _sdk->zm_crc32_checksum_size();
    printf("crc32 checksum size: %d\n", _size);
    #endif
}

void test_case_crc32(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "crc32.txt", test_vec)){
        printf("read test vector data failed\n");
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

        #if defined ZMCRYPTO_ALGO_CRC32
            CONTEXT_TYPE_PTR(crc32) ctx = _sdk->zm_crc32_new();
            uint8_t* output = new uint8_t[_sdk->zm_crc32_checksum_size()];
            _sdk->zm_crc32_init (ctx);
            _sdk->zm_crc32_starts (ctx);
            _sdk->zm_crc32_update (ctx, (uint8_t*)message.c_str(), message.length());
            _sdk->zm_crc32_final (ctx, output);
            _sdk->zm_crc32_free (ctx);

            if (checksum == std::string((char*)output, _sdk->zm_crc32_checksum_size())){
                format_output("%s by ZmCrypto|passed\n", algorithm.c_str());
            }
            else{
                format_output("%s by ZmCrypto|failed\n", algorithm.c_str());
            }

            delete[] output;
            output = NULL;
        #endif

        #if defined TEST_FOR_CRYPTOPP
            CryptoPP::HashTransformation* HashPtr = new CryptoPP::CRC32();
            HashPtr->Update((const CryptoPP::byte *)(uint8_t*)message.c_str(), message.length());
            CryptoPP::SecByteBlock digest(HashPtr->DigestSize());
            HashPtr->Final (digest);

            CryptoPP::SecByteBlock digest2(HashPtr->DigestSize());\
            memcpy(digest2 + 0, digest + 3, 1);\
            memcpy(digest2 + 1, digest + 2, 1);\
            memcpy(digest2 + 2, digest + 1, 1);\
            memcpy(digest2 + 3, digest + 0, 1);\

            if (checksum == std::string((char*)(CryptoPP::byte *)digest2, HashPtr->DigestSize())){
                format_output("%s by Crypto++|passed\n", algorithm.c_str());
            }
            else{
                format_output("%s by Crypto++|failed\n", algorithm.c_str());
            }

            delete HashPtr;
            HashPtr = NULL;
        #endif
    }
}

void test_speed_crc32(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_CRC32
        zmcrypto::sdk sdk;
        CONTEXT_TYPE_PTR(crc32) ctx = _sdk->zm_crc32_new();
        uint8_t* output = new uint8_t[_sdk->zm_crc32_checksum_size()];
        _sdk->zm_crc32_init (ctx);
        _sdk->zm_crc32_starts (ctx);

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            _sdk->zm_crc32_update (ctx, (uint8_t*)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed * 1000;
        format_output("crc32|%.2f KB/s\n", rate);

        _sdk->zm_crc32_final (ctx, output);
        _sdk->zm_crc32_free (ctx);

        delete[] output;
        output = NULL;
    #endif
}