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
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"
#include "test_base64.h"
#include "test_adler32.h"
#include "test_crc32.h"
#include "test_md5.h"
#include "test_sha1.h"
#include "test_sm3.h"
#include "test_hmac.h"
#include "test_cmac.h"
#include "test_ccm.h"
#include "test_pbkdf2.h"
#include "test_aes.h"
#include "test_des.h"
#include "test_rc4.h"
#include "test_blowfish.h"
#include "test_engine.h"
#include "test_config.h"
#include "test_blockpad.h"
#include "machine_info.h"
#include "format_output.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#if defined _DEBUG && defined _WIN32
    #include<crtdbg.h>
#endif

void print_env(){
   zmcrypto::sdk _sdk;
   uint32_t ver = _sdk.zm_version_num();
   const char* verstr = _sdk.zm_version_str();

   if (ver){
       printf ("Version number: 0x%08x\nVersion string: %s\n", ver, verstr);
   }

   format_output(".|completed\n");

   printf ("Date Time: %s\n", get_datetime().c_str());
   printf ("OS: %s\n",  get_os().c_str());
   printf ("CPU: %s\n", get_cpu().c_str());
   printf ("Memory: %s\n", get_memory().c_str());
   printf ("Compiler: %s\n", get_compiler().c_str());

   format_output(".|completed\n");
}

void test_case(zmcrypto::sdk* _sdk){
    // test_case_blockpad(_sdk);
    // test_case_blockdepad(_sdk);

    // test_case_base64(_sdk);
    // test_case_base64_line_break(_sdk);

    // test_case_adler32(_sdk);
    // test_case_crc32(_sdk);
    // test_case_md5(_sdk);
    // test_case_sha1(_sdk);
    test_case_sm3(_sdk);

    // test_case_hmac(_sdk);
    // test_case_cmac(_sdk);
    // test_case_ccm(_sdk);
    // test_case_pbkdf2(_sdk);

    // test_case_blowfish_ecb(_sdk);
    // test_case_blowfish_cbc(_sdk);
    // test_case_blowfish_cfb(_sdk);
    // test_case_blowfish_ofb(_sdk);
    // test_case_blowfish_ctr(_sdk);

    // test_case_aes_ecb(_sdk);
    // test_case_aes_cbc(_sdk);
    // test_case_aes_cfb(_sdk);
    // test_case_aes_ofb(_sdk);
    // test_case_aes_ctr(_sdk);

    // test_case_des_ecb(_sdk);
    // test_case_des_cbc(_sdk);
    // test_case_des_cfb(_sdk);
    // test_case_des_ofb(_sdk);
    // test_case_des_ctr(_sdk);
}

void test_engine(zmcrypto::sdk* _sdk){
    // test_case_engine_aes(_sdk);
    // test_case_engine_md5(_sdk);
}

void test_speed(zmcrypto::sdk* _sdk){
    //  test_speed_adler32(_sdk);
    //  test_speed_crc32(_sdk);
    //  test_speed_md5(_sdk);
    //  test_speed_sha1(_sdk);
    //  test_speed_aes(_sdk);
    //  test_speed_des(_sdk);
    //  test_speed_blowfish(_sdk);
}

void test_info(zmcrypto::sdk* _sdk){
    // test_info_adler32(_sdk);
    // test_info_crc32(_sdk);
    // test_info_md5(_sdk);
    // test_info_sha1(_sdk);
    // test_info_aes(_sdk);
    // test_info_des(_sdk);
    // test_info_blowfish(_sdk);
    // test_info_rc4(_sdk);
}

// void test_sm3(zmcrypto::sdk* _sdk){
//     // CONTEXT_TYPE_PTR(sm3) ctx = _sdk->zm_sm3_new ();
//     // uint32_t digestSize = _sdk->zm_sm3_digest_size();
//     // uint8_t* output = new uint8_t[digestSize];
//     // _sdk->zm_sm3_init (ctx);
//     // _sdk->zm_sm3_starts (ctx);
//     // _sdk->zm_sm3_update (ctx, (uint8_t*)"zhangluduo", 10);
//     // _sdk->zm_sm3_final (ctx, output);
//     // _sdk->zm_sm3_free (ctx);

//     // /* 8c ce b4 25 c8 a8 54 a5 9c 5e a6 dd a2 6a cb 3f 32 58 37 c7 da a5 47 a5 4f 9d 91 27 df 4c a9 fd */
//     // for (uint32_t i = 0; i < digestSize; i++){
//     //     printf ("%02x ", output[i]);
//     // }   printf ("\n");

//     // delete[] output;
//     // output = NULL;

// }

int main()
{
    zmcrypto::sdk _sdk;
    srand(time(NULL));
    print_env();
    //test_sm3(&_sdk);
    //return 0;

    test_case(&_sdk);
    test_speed(&_sdk);
    test_info(&_sdk);

#if defined _DEBUG && defined _WIN32
	char* s = new char[111];
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    return 0;
}
