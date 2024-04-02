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
#include "test_blockpad.h"

namespace{
    void cb_rng_get_bytes (uint8_t* data, uint32_t dlen)
    {
        for (uint32_t i = 0; i < dlen; i++){
            data[i] = rand() % 255;
        }
    }
}

void test_case_blockpad(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_BLOCKPAD
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
        uint32_t dlen = 10;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockpad_zero(data, dlen, block, blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "zero padding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
        uint32_t dlen = 10;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockpad_ansix923(data, dlen, block, blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "ansix923 padding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
        uint32_t dlen = 10;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockpad_pkcs7(data, dlen, block, blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "pkcs7 padding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
        uint32_t dlen = 10;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockpad_iso10126(data, dlen, block, blen, cb_rng_get_bytes);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "iso10126 padding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    #endif
}

void test_case_blockdepad(zmcrypto::sdk* _sdk)
{
    #if defined ZMCRYPTO_ALGO_BLOCKPAD
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        uint32_t dlen = 16;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockdepad_zero(data, dlen, block, &blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "zero depadding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0xb7, 0x24, 0x3a, 0x17, 0x69, 0x06 };
        uint32_t dlen = 16;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockdepad_iso10126(data, dlen, block, &blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "iso10126 depadding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 };
        uint32_t dlen = 16;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockdepad_ansix923(data, dlen, block, &blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "ansix923 depadding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    {
        uint8_t data[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06 };
        uint32_t dlen = 16;
        uint8_t block[16] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        uint32_t blen = 16;
        zmerror err = _sdk->zm_blockdepad_pkcs7(data, dlen, block, &blen);
        if (ZMCRYPTO_IS_ERROR(err)){
        printf ("%s\n", _sdk->zm_error_str(err));
        return;
        }

        printf ("%25s", "pkcs7 depadding: ");
        for (uint32_t i = 0; i < blen; i++){
            printf ("%02x ", block[i]);
        }   printf ("\n");
    }
    #endif
}
