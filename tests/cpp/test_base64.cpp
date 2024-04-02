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
#include "test_base64.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/base64.h"
    using namespace CryptoPP;
#endif

#include <string>

void test_case_base64(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "base64.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

	for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, message, table, result;
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "message", message)){
            printf("get key-value pair failed: message\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "table", table)){
            printf("get key-value pair failed: table\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "result", result)){
            printf("get key-value pair failed: digest\n");
            return;
        }

        if (table != "0" && table != "1"){
            printf ("table: %s\n", table.c_str());
            return;
        }

        {
            zmerror err;
            uint32_t olen = 0;
            uint32_t options = atoi(table.c_str());
            err = _sdk->zm_base64_encode((uint8_t*)(message.c_str()), message.length(), NULL, &olen, options);
            if (err != ZMCRYPTO_ERR_OVERFLOW){
                format_output("%s by ZmCrypto|failed\n", "base64");
                return;
            }

            uint8_t* output = new uint8_t[olen];
            err = _sdk->zm_base64_encode((uint8_t*)(message.c_str()), message.length(), output, &olen, options);
            if (ZMCRYPTO_IS_ERROR(err)){
                delete[] output;
                output = NULL;
                format_output("%s by ZmCrypto|failed\n", "base64");
                return;
            }

            if (result == (char*)output){
                format_output("%s by ZmCrypto|passed\n", "base64");
            }
            else{
                format_output("%s by ZmCrypto|failed\n", "base64");
            }

            delete[] output;
            output = NULL;
        }
        {
            zmerror err;

            uint32_t olen = 0;
            uint32_t options = atoi(table.c_str());
            err = _sdk->zm_base64_decode((uint8_t*)(result.c_str()), result.length(), NULL, &olen, options);
            if (err != ZMCRYPTO_ERR_OVERFLOW){
                format_output("%s by ZmCrypto|failed\n", "base64");
                return;
            }

            uint8_t* output = new uint8_t[olen];
            err = _sdk->zm_base64_decode((uint8_t*)(result.c_str()), result.length(), output, &olen, options);
            if (ZMCRYPTO_IS_ERROR(err)){
                delete[] output;
                output = NULL;
                format_output("%s by ZmCrypto|failed (%s)\n", "base64", _sdk->zm_error_str(err));
                return;
            }

            uint32_t rlen = message.length();
            if (rlen == olen && memcmp(output, message.c_str(), olen) == 0){
                format_output("%s by ZmCrypto|passed\n", "base64");
            }
            else{
                format_output("%s by ZmCrypto|failed\n", "base64");
            }

            delete[] output;
            output = NULL;
        }

        #if defined TEST_FOR_CRYPTOPP
        {
            Base64Encoder * Enc = new Base64Encoder();
            if (table == "0"){
                const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                AlgorithmParameters params = MakeParameters(Name::EncodingLookupArray(),(const CryptoPP::byte *)ALPHABET)(Name::InsertLineBreaks(), false);
                Enc->IsolatedInitialize(params);
            }
            else{
                const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                AlgorithmParameters params = MakeParameters(Name::EncodingLookupArray(),(const CryptoPP::byte *)ALPHABET)(Name::InsertLineBreaks(), false);
                Enc->IsolatedInitialize(params);
            }


            Enc->Put2 ((const CryptoPP::byte *)(message.c_str()), message.length(), 1, true/* must be true, otherwise throw an exception*/);

            SecByteBlock output(200);
            memset(output, 0, 200);
            size_t Len = Enc->Get(output, 200);

            if (std::string((char*)(void*)output) == result){
                format_output("%s by Crypto++|passed\n", "base64");
            }
            else{
                format_output("%s by Crypto++|failed\n", "base64");
            }

            delete Enc;
            Enc = NULL;
        }
        {
            Base64Decoder * Dec = new Base64Decoder(NULL);
            if (table == "0"){
                const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                int lookup[256];
                Base64Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 64, false);
                AlgorithmParameters params = MakeParameters(Name::DecodingLookupArray(),(const int *)lookup);
                Dec->IsolatedInitialize(params);
            }
            else{
                const CryptoPP::byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                int lookup[256];
                Base64Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 64, false);
                AlgorithmParameters params = MakeParameters(Name::DecodingLookupArray(),(const int *)lookup);
                Dec->IsolatedInitialize(params);
            }


            Dec->Put2 ((const CryptoPP::byte *)(result.c_str()), result.length(), 1, true/* must be true, otherwise throw an exception*/);
            SecByteBlock output(200);
            memset(output, 0, 200);
            size_t Len = Dec->Get(output, 200);

            if (std::string((char*)(void*)output) == message){
                format_output("%s by Crypto++|passed\n", "base64");
            }
            else{
                format_output("%s by Crypto++|failed\n", "base64");
            }

            delete Dec;
            Dec = NULL;
        }
        #endif
    } /* for */
}


void test_case_base64_line_break(zmcrypto::sdk* _sdk)
{
    {
        uint8_t input[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        uint32_t ilen = sizeof(input);

        /*
            AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcI
            CQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=

            md5=81701f7c76f7999c36e7bad1b1b36b30
        */

        zmerror err;
        uint32_t olen = 0;
        uint32_t options = 76 << 16 | 0 >> 16; /* table 0 and Add '\n' one line 76 bytes */
        err = _sdk->zm_base64_encode(input, ilen, NULL, &olen, options);
        if (err != ZMCRYPTO_ERR_OVERFLOW){
            format_output("%s by ZmCrypto|failed\n", "base64");
            return;
        }

        uint8_t* output = new uint8_t[olen];
        err = _sdk->zm_base64_encode(input, ilen, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            delete[] output;
            output = NULL;
            format_output("%s by ZmCrypto|failed\n", "base64");
            return;
        }

        printf("%s\n", (char*)output);

        CONTEXT_TYPE_PTR(md5) ctx = _sdk->zm_md5_new();
        uint8_t* digest = new uint8_t[_sdk->zm_md5_digest_size()];
        _sdk->zm_md5_init (ctx);
        _sdk->zm_md5_starts (ctx);
        _sdk->zm_md5_update (ctx, output, olen);
        _sdk->zm_md5_final (ctx, digest);
        _sdk->zm_md5_free (ctx);

        if (memcmp(digest, "\x81\x70\x1f\x7c\x76\xf7\x99\x9c\x36\xe7\xba\xd1\xb1\xb3\x6b\x30", _sdk->zm_md5_digest_size()) == 0){
            format_output("%s by ZmCrypto|passed\n", "base64");
        }
        else{
            format_output("%s by ZmCrypto|failed\n", "base64");
        }

        delete[] digest;
        digest = NULL;

        delete[] output;
        output = NULL;
    }

    {
        const char* input = 
            "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcI\n"
            "CQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=";

        uint32_t ilen = std::string(input).length();

        zmerror err;

        uint32_t olen = 0;
        uint32_t options = 1 << 16 | 0 >> 16; /* table 0 and skip whitespace */
        err = _sdk->zm_base64_decode((uint8_t*)(input), ilen, NULL, &olen, options);
        if (err != ZMCRYPTO_ERR_OVERFLOW){
            format_output("%s by ZmCrypto|failed\n", "base64");
            return;
        }

        uint8_t* output = new uint8_t[olen];
        err = _sdk->zm_base64_decode((uint8_t*)(input), ilen, output, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            delete[] output;
            output = NULL;
            format_output("%s by ZmCrypto|failed (%s)\n", "base64", _sdk->zm_error_str(err));
            return;
        }

        uint8_t codes[] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        uint32_t rlen = sizeof(codes);
        if (rlen == olen && memcmp(output, codes, olen) == 0){
            format_output("%s by ZmCrypto|passed\n", "base64");
        }
        else{
            format_output("%s by ZmCrypto|failed\n", "base64");
        }

        delete[] output;
        output = NULL;
    }
    {
        const char* input = 
            "AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcI\n"
            "CQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=";

        uint32_t ilen = std::string(input).length();

        zmerror err;

        uint32_t olen = 0;
        uint32_t options = 0 << 16 | 0 >> 16; /* table 0 and not skip whitespace */
        err = _sdk->zm_base64_decode((uint8_t*)(input), ilen, NULL, &olen, options);
        if (err != ZMCRYPTO_ERR_OVERFLOW){
            format_output("%s by ZmCrypto|failed\n", "base64");
            return;
        }

        uint8_t* output = new uint8_t[olen];
        err = _sdk->zm_base64_decode((uint8_t*)(input), ilen, output, &olen, options);

        if (err == ZMCRYPTO_ERR_INVALID_CHAR){
            /* because 'options' not skip whitespace, so should return 'ZMCRYPTO_ERR_INVALID_CHAR' */
            format_output("%s by ZmCrypto|passed (%s)\n", "base64", _sdk->zm_error_str(err));
        }
        else{
            format_output("%s by ZmCrypto|failed\n", "base64");
        }

        delete[] output;
        output = NULL;
    }
}
