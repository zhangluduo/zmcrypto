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
#include "test_sm4.h"
#include "test_blowfish.h"
#include "test_engine.h"
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
    test_case_blockpad(_sdk);
    test_case_blockdepad(_sdk);

    test_case_base64(_sdk);
    test_case_base64_line_break(_sdk);

    test_case_adler32(_sdk);
    test_case_crc32(_sdk);
    test_case_md5(_sdk);
    test_case_sha1(_sdk);
    test_case_sm3(_sdk);

    test_case_hmac(_sdk);
    test_case_cmac(_sdk);
    test_case_ccm(_sdk);
    test_case_pbkdf2(_sdk);

    test_case_blowfish_ecb(_sdk);
    test_case_blowfish_cbc(_sdk);
    test_case_blowfish_cfb(_sdk);
    test_case_blowfish_ofb(_sdk);
    test_case_blowfish_ctr(_sdk);

    test_case_aes_ecb(_sdk);
    test_case_aes_cbc(_sdk);
    test_case_aes_cfb(_sdk);
    test_case_aes_ofb(_sdk);
    test_case_aes_ctr(_sdk);

    test_case_des_ecb(_sdk);
    test_case_des_cbc(_sdk);
    test_case_des_cfb(_sdk);
    test_case_des_ofb(_sdk);
    test_case_des_ctr(_sdk);

    test_case_sm4_ecb(_sdk);
    test_case_sm4_cbc(_sdk);
    test_case_sm4_cfb(_sdk);
    test_case_sm4_ofb(_sdk);
    test_case_sm4_ctr(_sdk);
}

void test_engine(zmcrypto::sdk* _sdk){
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
    test_speed_adler32(_sdk);
    test_speed_crc32(_sdk);
    test_speed_md5(_sdk);
    test_speed_sha1(_sdk);
    test_speed_sm3(_sdk);
    test_speed_aes(_sdk);
    test_speed_des(_sdk);
    test_speed_blowfish(_sdk);
}

void test_info(zmcrypto::sdk* _sdk){
    test_info_adler32(_sdk);
    test_info_crc32(_sdk);
    test_info_md5(_sdk);
    test_info_sha1(_sdk);
    test_info_sm3(_sdk);
    test_info_aes(_sdk);
    test_info_des(_sdk);
    test_info_blowfish(_sdk);
    test_info_rc4(_sdk);
    test_info_sm4(_sdk);
}

void temp_test_sha3(zmcrypto::sdk* _sdk)
{
    {
        uint8_t* output = new uint8_t[_sdk->zm_sha3_224_digest_size()];
        struct sha3_224_ctx* ctx = _sdk->zm_sha3_224_new();
        _sdk->zm_sha3_224_init (ctx);
        _sdk->zm_sha3_224_starts (ctx);
        _sdk->zm_sha3_224_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha3_224_final (ctx, output);
        for (int i = 0 ;i < 224/8; i++){
            printf ("%02x ", output[i]);
        }   printf ("\n");
        _sdk->zm_sha3_224_free(ctx);
        delete[] output;
        output = NULL;
    }
    {
        uint8_t* output = new uint8_t[_sdk->zm_sha3_256_digest_size()];
        struct sha3_256_ctx* ctx = _sdk->zm_sha3_256_new();
        _sdk->zm_sha3_256_init (ctx);
        _sdk->zm_sha3_256_starts (ctx);
        _sdk->zm_sha3_256_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha3_256_final (ctx, output);
        for (int i = 0 ;i < 256/8; i++){
            printf ("%02x ", output[i]);
        }   printf ("\n");
        _sdk->zm_sha3_256_free(ctx);
        delete[] output;
        output = NULL;
    }
    {
        uint8_t* output = new uint8_t[_sdk->zm_sha3_384_digest_size()];
        struct sha3_384_ctx* ctx = _sdk->zm_sha3_384_new();
        _sdk->zm_sha3_384_init (ctx);
        _sdk->zm_sha3_384_starts (ctx);
        _sdk->zm_sha3_384_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha3_384_final (ctx, output);
        for (int i = 0 ;i < 384/8; i++){
            printf ("%02x ", output[i]);
        }   printf ("\n");
        _sdk->zm_sha3_384_free(ctx);
        delete[] output;
        output = NULL;
    }
    {
        uint8_t* output = new uint8_t[_sdk->zm_sha3_512_digest_size()];
        struct sha3_512_ctx* ctx = _sdk->zm_sha3_512_new();
        _sdk->zm_sha3_512_init (ctx);
        _sdk->zm_sha3_512_starts (ctx);
        _sdk->zm_sha3_512_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha3_512_final (ctx, output);
        for (int i = 0 ;i < 512/8; i++){
            printf ("%02x ", output[i]);
        }   printf ("\n");
        _sdk->zm_sha3_512_free(ctx);
        delete[] output;
        output = NULL;
    }
    /*
6b 53 2f 4a 1d 50 5b 2c 9b 57 86 16 47 c6 9a c5 cd 98 8a 01 74 3d a4 4d 25 cc 94 a0
23 f9 1a 2a 16 af fd b9 00 75 ee 58 d7 95 a9 18 29 0e ca e3 3a 86 00 0a 5d 8e ea bf 7b af e6 b4
b4 e4 a2 1c 5e e1 b5 3f 7e 99 ab 55 9d 7a c1 ff 43 64 48 15 49 2f c5 5d 0b 26 36 53 7b 1c b5 7a 6d 51 7f 46 91 27 37 3a c8 ab 6d fd 3c 34 f0 0d
1f fe bf 42 45 9c fb 4f d5 f6 44 79 fb a8 ad 0f 34 9e 4e 25 1f c0 cd 68 25 32 fc 30 9b 6e 37 07 df 99 6b 9e 6a 19 6e 4f 1f 89 91 8d 08 fa 34 0d a2 a8 1c 4f 2c 1b 1f 94 77 19 85 65 b7 9d 85 63
    */
}

void temp_test_sha2(zmcrypto::sdk* _sdk)
{
    {
        uint8_t out[28];
        struct sha224_ctx* ctx = _sdk->zm_sha224_new ();
        _sdk->zm_sha224_starts (ctx);
        _sdk->zm_sha224_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha224_final (ctx, out);
        for (int i = 0; i < 28; i++){
            printf("%02x ", out[i]);
        }   printf (",\n");
        _sdk->zm_sha224_free (ctx);
    }
    {
        uint8_t out[32];
        struct sha256_ctx* ctx = _sdk->zm_sha256_new ();
        _sdk->zm_sha256_starts (ctx);
        _sdk->zm_sha256_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha256_final (ctx, out);
        for (int i = 0; i < 32; i++){
            printf("%02x ", out[i]);
        }   printf (",\n");
        _sdk->zm_sha256_free (ctx);
    }
    {
        uint8_t out[48];
        struct sha384_ctx* ctx = _sdk->zm_sha384_new ();
        _sdk->zm_sha384_starts (ctx);
        _sdk->zm_sha384_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha384_final (ctx, out);
        for (int i = 0; i < 48; i++){
            printf("%02x ", out[i]);
        }   printf (",\n");
        _sdk->zm_sha384_free (ctx);
    }
    {
        uint8_t out[64];
        struct sha512_ctx* ctx = _sdk->zm_sha512_new ();
        _sdk->zm_sha512_starts (ctx);
        _sdk->zm_sha512_update (ctx, (uint8_t*)"zhangluduo", 10);
        _sdk->zm_sha512_final (ctx, out);
        for (int i = 0; i < 64; i++){
            printf("%02x ", out[i]);
        }   printf (",\n");
        _sdk->zm_sha512_free (ctx);
    }
// 72 12 b9 0b d4 ef 65 6e 72 ac 45 45 76 7a 5a 80 f4 a2 c2 3f f2 3f b2 bc c2 0b ba b3 ,
// e5 7f f8 b2 95 4f 39 d6 6b 7d 95 05 78 b1 ec 57 40 28 2f b9 a1 68 e9 0c 9d 16 0e 43 a6 d2 57 74 ,
// a1 59 53 26 66 32 32 c2 d5 9d 99 cc d8 14 bb fa 51 a3 52 1b 0d fc 8a 39 51 ab aa 6c 0d 2e 54 62 36 16 08 85 dc f0 ae 5f ae 61 ac 7c 46 91 47 1c ,
// 9f 90 b2 00 67 0a bd 82 84 79 af fa ef d2 59 8a b3 0d f0 d8 fc d3 40 b9 54 f5 82 7f 99 48 5c 35 c1 36 1b f0 89 88 5b 92 4f 20 1a 03 91 b0 ce 7d fc 89 69 05 16 f5 40 b4 d5 2f 18 2f 5c af e8 d6 ,

}

void temp_test_xtea(zmcrypto::sdk* _sdk)
{
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t pt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t ct[] = {0xFF, 0xC5, 0x2D, 0x10, 0xA0, 0x10, 0x01, 0x0B};
    uint8_t pt2[8];
    uint8_t ct2[8];
    {
        struct xtea_ctx* ctx = _sdk->zm_xtea_new();
        _sdk->zm_xtea_set_dkey(ctx, key, 16);
        _sdk->zm_xtea_dec_block(ctx, ct, pt2);
        for (int i = 0; i < 8; i++){
            printf ("%02x ", pt2[i]);
        }   printf ("\n");
        _sdk->zm_xtea_free(ctx);
    }
    {

        struct xtea_ctx* ctx = _sdk->zm_xtea_new();
        _sdk->zm_xtea_set_ekey(ctx, key, 16);
        _sdk->zm_xtea_enc_block(ctx, pt, ct2);
        for (int i = 0; i < 8; i++){
            printf ("%02x ", ct2[i]);
        }   printf ("\n");
        _sdk->zm_xtea_free(ctx);
    }
// 00 01 02 03 04 05 06 07 
// ff c5 2d 10 a0 10 01 0b 
}

void temp_test_base16(zmcrypto::sdk* _sdk)
{
    {
        const char* s = "abcdefg"; /*61 62 63 64 65 66 67*/
        uint32_t len = strlen(s);
        uint32_t options = 1 << 16 | 0;
        uint32_t olen = 0;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, 0, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 28){
                printf ("successed \n");
            }
            else{
                printf ("failed \n");
            }
        }
    }
    {
        const char* s = "abcdefg";
        uint32_t len = strlen(s);
        uint32_t options = 4 << 16 | 0;
        uint32_t olen = 0;
        zmerror err = _sdk->zm_base16_encode((uint8_t*)s, len, 0, &olen, options);
        if (ZMCRYPTO_IS_ERROR(err)){
            printf ("err: %08x", err);
        }
        else{
            if (olen == 17){
                printf ("successed \n");
            }
            else{
                printf ("failed \n");
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
            printf ("successed \n");
        }else{
            printf ("failed \n");
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
                printf ("successed \n");
            }else{
                printf ("failed \n");
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
                printf ("successed \n");
            }else{
                printf ("failed \n");
            }
        }
    }
    // ===
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
                printf ("successed \n");
            }else{
                printf ("failed \n");
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
            printf ("successed \n");
        }
        else{
            printf ("failed \n");
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
            printf ("successed \n");
        }
        else{
            printf ("failed \n");
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
                printf ("successed \n");
            }else{
                printf ("failed \n");
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
            printf ("successed \n");
        }
        else{
            printf ("failed \n");
        }
    }
}
zmcrypto::sdk *_sdk2;
#if defined ZMCRYPTO_ALGO_AES       
    void*   _aes_new            (void) { return _sdk2->zm_aes_new(); }
    void    _aes_free           (void* ctx) { _sdk2->zm_aes_free((aes_ctx*)ctx); }
    void    _aes_init           (void* ctx) { _sdk2->zm_aes_init((aes_ctx*)ctx); }
    int32_t _aes_block_size     (void) { return _sdk2->zm_aes_block_size(); }
    int32_t _aes_ksize_min      (void) { return _sdk2->zm_aes_ksize_min(); }
    int32_t _aes_ksize_max      (void) { return _sdk2->zm_aes_ksize_max(); }
    int32_t _aes_ksize_multiple (void) { return _sdk2->zm_aes_ksize_multiple(); }
    int32_t _aes_set_ekey(void* ctx, uint8_t* key, uint32_t ksize) { int32_t ret = _sdk2->zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); return ret; }
    int32_t _aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return _sdk2->zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
    void    _aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return _sdk2->zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
    void    _aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return _sdk2->zm_aes_enc_block((aes_ctx*)ctx, ciphertext, plaintext); }
#endif
void temp_test_gcm(zmcrypto::sdk *_sdk){
    _sdk2 = _sdk;
    //Crypto++
    // Key: feffe9928665731c6d6a8f9467308308
    // IV:  cafebabefacedbaddecaf888
    // Header: feedfacedeadbeeffeedfacedeadbeefabaddad2
    // Plaintext: d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72 1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    // Ciphertext: 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091
    // MAC: 5bc94fbc3221a5db94fae95ae7121a47

    uint8_t key[] = { 
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08 };

    uint8_t tag[] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
    };

    uint32_t klen = 16;

    uint8_t iv[] = { 
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 
        0xde, 0xca, 0xf8, 0x88};

    uint32_t ivlen = 12;

    uint8_t aad[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2 };

    uint32_t aadlen = 20;

    uint8_t pt[] = { 
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 
        0xba, 0x63, 0x7b, 0x39};

    uint8_t ct[] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 
        0x3d, 0x58, 0xe0, 0x91};

    uint32_t ptlen = 60;

    uint8_t pt2[60];
    uint8_t ct2[60];

    uint8_t tag2[16];
    uint32_t taglen = 16;
    {

        struct gcm_ctx* ctx = _sdk->zm_gcm_new ();
        _sdk->zm_gcm_init(ctx, 
            _aes_new           ,
            _aes_free          ,
            _aes_init          ,
            _aes_block_size    ,
            _aes_ksize_min     ,
            _aes_ksize_max     ,
            _aes_ksize_multiple,
            _aes_set_ekey      ,
            _aes_set_dkey      ,
            _aes_enc_block     ,
            _aes_dec_block     );

        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_starts (ctx, key, klen, iv, ivlen, DO_ENCRYPT)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_aad (ctx, aad, 10)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_aad (ctx, aad+10, 10)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_data (ctx, pt, 30, ct2)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_data (ctx, pt+30, 30, ct2+30)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_final(ctx, tag2, 16)) {}

        for (int i = 0; i < 60; i++){
            printf ("%02x ", ct2[i]);
        }   printf ("\n");

        for (int i = 0; i < 16; i++){
            printf ("%02x ", tag2[i]);
        }   printf ("\n");

        if (memcmp(ct, ct2, 60) == 0 && memcmp(tag, tag2, 16) == 0){
            printf ("successed \n");
        }
        else{
            printf ("failed \n");
        }

        _sdk->zm_gcm_free (ctx);
    }

    {

        struct gcm_ctx* ctx = _sdk->zm_gcm_new ();
        _sdk->zm_gcm_init(ctx, 
            _aes_new           ,
            _aes_free          ,
            _aes_init          ,
            _aes_block_size    ,
            _aes_ksize_min     ,
            _aes_ksize_max     ,
            _aes_ksize_multiple,
            _aes_set_ekey      ,
            _aes_set_dkey      ,
            _aes_enc_block     ,
            _aes_dec_block     );

        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_starts (ctx, key, klen, iv, ivlen, DO_DECRYPT)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_aad (ctx, aad, 10)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_aad (ctx, aad+10, 10)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_data (ctx, ct, 30, pt2)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_update_data (ctx, ct+30, 30, pt2+30)) {}
        if (ZMCRYPTO_ERR_SUCCESSED != _sdk->zm_gcm_final(ctx, tag2, 16)) {}

        for (int i = 0; i < 60; i++){
            printf ("%02x ", pt2[i]);
        }   printf ("\n");

        for (int i = 0; i < 16; i++){
            printf ("%02x ", tag2[i]);
        }   printf ("\n");

        if (memcmp(pt, pt2, 60) == 0 && memcmp(tag, tag2, 16) == 0){
            printf ("successed \n");
        }
        else{
            printf ("failed \n");
        }

        _sdk->zm_gcm_free (ctx);
    }
}

void temp_test_md2(zmcrypto::sdk *_sdk){
    uint8_t out[64];
    struct md2_ctx* ctx = _sdk->zm_md2_new ();
    _sdk->zm_md2_starts (ctx);
    _sdk->zm_md2_update (ctx, (uint8_t*)"zhangluduo", 10);
    _sdk->zm_md2_final (ctx, out);
    for (int i = 0; i < 16; i++){
        printf("%02x ", out[i]);
    }   printf (",\n");
    _sdk->zm_md2_free (ctx);
    // 43 cf c2 a1 05 3e 21 dd e3 58 76 06 a6 d6 bd eb
}

void temp_test_md4(zmcrypto::sdk *_sdk){
    uint8_t out[64];
    struct md4_ctx* ctx = _sdk->zm_md4_new ();
    _sdk->zm_md4_starts (ctx);
    _sdk->zm_md4_update (ctx, (uint8_t*)"zhangluduo", 10);
    _sdk->zm_md4_final (ctx, out);
    for (int i = 0; i < 16; i++){
        printf("%02x ", out[i]);
    }   printf (",\n");
    _sdk->zm_md4_free (ctx);
    // 59 08 d7 47 da b0 4b 22 da 9f 5f 62 ee 63 8e 5d
}

void temp_test_ed2k(zmcrypto::sdk *_sdk){
    uint8_t out[64];
    struct ed2k_ctx* ctx = _sdk->zm_ed2k_new ();
    _sdk->zm_ed2k_starts (ctx);
    for (int i = 0; i < 972801; i++){
        _sdk->zm_ed2k_update (ctx, (uint8_t*)"zhangluduo", 10);
    }
    _sdk->zm_ed2k_final (ctx, out);
    for (int i = 0; i < 16; i++){
        printf("%02x ", out[i]);
    }   printf (",\n");
    _sdk->zm_ed2k_free (ctx);
    // fe 14 fd c1 12 4b 5a 40 1e 3c 31 84 eb 3a d5 1d
}

int main()
{
    zmcrypto::sdk _sdk;

    // temp_test_sha3(&_sdk);
    // temp_test_sha2(&_sdk);
    // temp_test_md2(&_sdk);
    // temp_test_md4(&_sdk);
    // temp_test_ed2k(&_sdk);
    // temp_test_xtea(&_sdk);
    // temp_test_base16(&_sdk);
    // temp_test_gcm(&_sdk);

    // return 1;
    
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

    test_engine(&_sdk);
    // test_case(&_sdk);
    // test_speed(&_sdk);
    // test_info(&_sdk);
#endif

#if defined _DEBUG && defined _WIN32
	char* s = new char[111];
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    return 0;
}


