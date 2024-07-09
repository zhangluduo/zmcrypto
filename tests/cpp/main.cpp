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
#include "test_base16.h"
#include "test_base64.h"
#include "test_adler32.h"
#include "test_crc32.h"
#include "test_md2.h"
#include "test_md4.h"
#include "test_md5.h"
#include "test_ed2k.h"
#include "test_sha1.h"
#include "test_sha2.h"
#include "test_sha3.h"
#include "test_sm3.h"
#include "test_hmac.h"
#include "test_cmac.h"
#include "test_ccm.h"
#include "test_gcm.h"
#include "test_pbkdf2.h"
#include "test_aes.h"
#include "test_des.h"
#include "test_rc4.h"
#include "test_sm4.h"
#include "test_xtea.h"
#include "test_blowfish.h"
#include "test_hook.h"
#include "test_config.h"
#include "test_blockpad.h"
#include "test_asn1.h"
#include "machine_info.h"
#include "format_output.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <vector>

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

    test_case_base16(_sdk);
    // test_case_base64(_sdk);
    // test_case_base64_line_break(_sdk);

    // test_case_adler32(_sdk);
    // test_case_crc32(_sdk);
    // test_case_md2(_sdk);
    // test_case_md4(_sdk);
    // test_case_md5(_sdk);
    // test_case_ed2k(_sdk);
    // test_case_sha1(_sdk);
    // test_case_sha2(_sdk);
    // test_case_sha3(_sdk);
    // test_case_sm3(_sdk);

    // test_case_hmac(_sdk);
    // test_case_cmac(_sdk);
    // test_case_ccm(_sdk);
    // test_case_gcm(_sdk);
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

    // test_case_sm4_ecb(_sdk);
    // test_case_sm4_cbc(_sdk);
    // test_case_sm4_cfb(_sdk);
    // test_case_sm4_ofb(_sdk);
    // test_case_sm4_ctr(_sdk);

    // test_case_xtea_ecb(_sdk);
    // test_case_xtea_cbc(_sdk);
    // test_case_xtea_cfb(_sdk);
    // test_case_xtea_ofb(_sdk);
    // test_case_xtea_ctr(_sdk);
}

void test_hook(zmcrypto::sdk* _sdk){
    test_case_hook_aes(_sdk);
    {
        test_case_aes_ecb(_sdk);
        test_case_aes_cbc(_sdk);
        test_case_aes_cfb(_sdk);
        test_case_aes_ofb(_sdk);
        test_case_aes_ctr(_sdk);
    }
    test_case_unhook_aes(_sdk);
    {
        test_case_aes_ecb(_sdk);
        test_case_aes_cbc(_sdk);
        test_case_aes_cfb(_sdk);
        test_case_aes_ofb(_sdk);
        test_case_aes_ctr(_sdk);
    }
}

void test_speed(zmcrypto::sdk* _sdk){
    // test_speed_adler32(_sdk);
    // test_speed_crc32(_sdk);
    // test_speed_md2(_sdk);
    // test_speed_md4(_sdk);
    // test_speed_md5(_sdk);
    // test_speed_ed2k(_sdk);
    // test_speed_sha1(_sdk);
    // test_speed_sha2(_sdk);
    // test_speed_sha3(_sdk);
    // test_speed_sm3(_sdk);
    // test_speed_sm4(_sdk);
    // test_speed_xtea(_sdk);
    // test_speed_aes(_sdk);
    // test_speed_des(_sdk);
    // test_speed_blowfish(_sdk);
}

void test_info(zmcrypto::sdk* _sdk){
    // test_info_adler32(_sdk);
    // test_info_crc32(_sdk);
    // test_info_md2(_sdk);
    // test_info_md4(_sdk);
    // test_info_md5(_sdk);
    // test_info_ed2k(_sdk);
    // test_info_sha1(_sdk);
    // test_info_sha2(_sdk);
    // test_info_sha3(_sdk);
    // test_info_sm3(_sdk);
    // test_info_aes(_sdk);
    // test_info_des(_sdk);
    // test_info_blowfish(_sdk);
    // test_info_rc4(_sdk);
    // test_info_sm4(_sdk);
    // test_info_xtea(_sdk);
}

int main()
{
    zmcrypto::sdk _sdk;

#if 1
    srand((unsigned int)time(NULL));
    print_env();

    // test_asn1_case1();
    // test_asn1_case2();
    // test_asn1_case3();
    // test_asn1_case4();
    // test_asn1_case5();
    // test_asn1_case6();
    // test_asn1_case7();
    // test_asn1_case8();
    // test_asn1_case9();
    // test_asn1_case10();
    // test_asn1_case11();
    // test_asn1_case12();
    // test_asn1_case13();
    // test_asn1_case14();
    // test_asn1_case15();
    // test_asn1_case16();
    // test_asn1_case17();
    // test_asn1_case18();

    // test_hook(&_sdk);
    test_case(&_sdk);
    // test_speed(&_sdk);
    // test_info(&_sdk);
#endif

#if defined _DEBUG && defined _WIN32
	char* s = new char[111];
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    return 0;
}


