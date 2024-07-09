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
#include "test_base16.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    using namespace CryptoPP;
#endif

#include <string>

void test_case_base16(zmcrypto::sdk* _sdk)
{
    {
        const char* s = "abcdefg"; /*61 62 63 64 65 66 67*/
        uint32_t len = strlen(s);
        uint32_t options = 1 << 16 | 0;
        uint32_t olen = 0;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, NULL, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 28){
                format_output("%s by zmcrypto|passed\n", "base16");
            }
            else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        const char* s = "abcdefg";
        uint32_t len = strlen(s);
        uint32_t options = 4 << 16 | 0;
        uint32_t olen = 0;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, NULL, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 17){
                format_output("%s by zmcrypto|passed\n", "base16");
            }
            else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        const char* s = "abcdefg";
        uint32_t len = strlen(s);
        uint32_t options = 1 << 16 | 0;
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, output, &olen, options);
        if (/*ZMCRYPTO_IS_ERROR(err)*/ err == ZMCRYPTO_ERR_OVERFLOW){
            format_output("%s by zmcrypto|passed\n", "base16");
        }else{
            format_output("%s by zmcrypto|failed\n", "base16");
        }
    }
    {
        const char* s = "abcdefg";
        uint32_t len = strlen(s);
        uint32_t options = 1 << 16 | 0;
        uint8_t output[30]; memset(output, 0, 20);
        uint32_t olen = 30;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 28 && memcmp(output, "6\n1\n6\n2\n6\n3\n6\n4\n6\n5\n6\n6\n6\n7\n", olen) == 0){
                format_output("%s by zmcrypto|passed\n", "base16");
            }else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        const char* s = "abcdefg";
        uint32_t len = strlen(s);
        uint32_t options = 4 << 16 | 0;
        uint8_t output[30]; memset(output, 0, 20);
        uint32_t olen = 30;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 17 && memcmp(output, "6162\n6364\n6566\n67", olen) == 0){
                format_output("%s by zmcrypto|passed\n", "base16");
            }else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        uint32_t options = 0 << 16 | 0;
        int8_t* b64 = (int8_t*)"61626364656667";
        uint32_t len = strlen((char*)b64);
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_decode((uint8_t*)b64, len, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 7 && memcmp(output, "abcdefg", olen) == 0){
                format_output("%s by zmcrypto|passed\n", "base16");
            }else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        uint32_t options = 0 << 16 | 0;
        int8_t* b64 = (int8_t*)"6162636\n4656667";
        uint32_t len = strlen((char*)b64);
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_decode((uint8_t*)b64, len, output, &olen, options);
        if (err == ZMCRYPTO_ERR_INVALID_CHAR){
                format_output("%s by zmcrypto|passed\n", "base16");
        }else{
                format_output("%s by zmcrypto|failed\n", "base16");
        }
    }
    {
        uint32_t options = 1 << 16 | 0;
        int8_t* b64 = (int8_t*)"6162636x4656667";
        uint32_t len = strlen((char*)b64);
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_decode((uint8_t*)b64, len, output, &olen, options);
        if (err == ZMCRYPTO_ERR_INVALID_CHAR){
            format_output("%s by zmcrypto|passed\n", "base16");
        }else{
            format_output("%s by zmcrypto|failed\n", "base16");
        }
    }
    {
        uint32_t options = 1 << 16 | 0;
        int8_t* b64 = (int8_t*)"61626\n36\r4656667";
        uint32_t len = strlen((char*)b64);
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_decode((uint8_t*)b64, len, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 7 && memcmp(output, "abcdefg", olen) == 0){
                format_output("%s by zmcrypto|passed\n", "base16");
            }else{
                format_output("%s by zmcrypto|failed\n", "base16");
            }
        }
    }
    {
        uint32_t options = 1 << 16 | 0;
        int8_t* b64 = (int8_t*)"616h26\n36\r4656667";
        uint32_t len = strlen((char*)b64);
        uint8_t output[20]; memset(output, 0, 20);
        uint32_t olen = 20;
        zmerror err = _sdk->zm_base16_decode((uint8_t*)b64, len, output, &olen, options);
        if (err == ZMCRYPTO_ERR_INVALID_CHAR){
            format_output("%s by zmcrypto|passed\n", "base16");
        }else{
            format_output("%s by zmcrypto|failed\n", "base16");
        }
    }
}

