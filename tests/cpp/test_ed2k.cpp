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
#include "test_ed2k.h"

#if defined TEST_FOR_CRYPTOPP
#endif

#if defined TEST_FOR_OPENSSL_SPEED
#endif

void test_info_ed2k(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_ED2K
    int32_t _size = _sdk->zm_ed2k_digest_size();
    int32_t _size2 = _sdk->zm_ed2k_block_size();
    printf("ed2k digest size: %d, block size: %d\n", _size, _size2);
    #endif
}


void test_case_ed2k(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "ed2k.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

	for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, message, digest, comment, repeat;
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

        #if defined ZMCRYPTO_ALGO_ED2K

            CONTEXT_TYPE_PTR(ed2k) ctx = _sdk->zm_ed2k_new();
            uint8_t* output = new uint8_t[_sdk->zm_ed2k_digest_size()];
            _sdk->zm_ed2k_init (ctx);
            _sdk->zm_ed2k_starts (ctx);
            for (uint32_t i = 0; i < loop;i ++){
				_sdk->zm_ed2k_update(ctx, (uint8_t*)message.c_str(), (uint32_t)message.length());
            }

            _sdk->zm_ed2k_final (ctx, output);
            _sdk->zm_ed2k_free (ctx);
            if (digest == std::string((char*)output, _sdk->zm_ed2k_digest_size())){
                format_output("%s by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        #endif

        #if defined TEST_FOR_CRYPTOPP
        #endif
    }
}

void test_speed_ed2k(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_ED2K
        
        CONTEXT_TYPE_PTR(ed2k) ctx = _sdk->zm_ed2k_new();
        uint8_t* output = new uint8_t[_sdk->zm_ed2k_digest_size()];
        _sdk->zm_ed2k_init (ctx);
        _sdk->zm_ed2k_starts (ctx);

        uint8_t msg[16] = { 0 };
        uint32_t mlen = 16;
        uint64_t start = get_timestamp_us();
        uint64_t end = 0;
        uint64_t dsize = 0;
        while (true)
        {
            _sdk->zm_ed2k_update (ctx, (uint8_t*)msg, mlen);
            dsize += mlen;
            end = get_timestamp_us();
            if (end - start >= TEST_TOTAL_SEC * 1000000)
                break;
        }
        uint32_t elapsed = (uint32_t)(end - start);
        double rate = (double)dsize / (double)elapsed;
        format_output("ed2k by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());

        _sdk->zm_ed2k_final (ctx, output);
        _sdk->zm_ed2k_free (ctx);

        delete[] output;
        output = NULL;
    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    {

    }
    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
    {

    }
    #endif
}