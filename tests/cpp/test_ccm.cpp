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
#include "vector_file.h"
#include "format_output.h"
#include "time_stamp.h"
#include "test_config.h"
#include "test_cmac.h"

#if defined TEST_FOR_CRYPTOPP
    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/cmac.h"
    #include "cryptopp820/include/aes.h"
    #include "cryptopp820/include/des.h"
    using namespace CryptoPP;
#endif

namespace{
    zmcrypto::sdk g_ccm_sdk;
    #if defined ZMCRYPTO_ALGO_AES       
             void*   _aes_new            (void) { return g_ccm_sdk.zm_aes_new(); }
             void    _aes_free           (void* ctx) { g_ccm_sdk.zm_aes_free((aes_ctx*)ctx); }
             void    _aes_init           (void* ctx) { g_ccm_sdk.zm_aes_init((aes_ctx*)ctx); }
             int32_t _aes_block_size     (void) { return g_ccm_sdk.zm_aes_block_size(); }
             int32_t _aes_ksize_min      (void) { return g_ccm_sdk.zm_aes_ksize_min(); }
             int32_t _aes_ksize_max      (void) { return g_ccm_sdk.zm_aes_ksize_max(); }
             int32_t _aes_ksize_multiple (void) { return g_ccm_sdk.zm_aes_ksize_multiple(); }
             int32_t _aes_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_ccm_sdk.zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); }
             int32_t _aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_ccm_sdk.zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
             void    _aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_ccm_sdk.zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
             void    _aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_ccm_sdk.zm_aes_enc_block((aes_ctx*)ctx, ciphertext, plaintext); }
    #endif
    #if defined ZMCRYPTO_ALGO_DES
            // void*   _des_new            (void) { return g_ccm_sdk.zm_des_new(); }
            // void    _des_free           (void* ctx) { g_ccm_sdk.zm_des_free((des_ctx*)ctx); }
            // void    _des_init           (void* ctx) { g_ccm_sdk.zm_des_init((des_ctx*)ctx); }
            // int32_t _des_block_size     (void) { return g_ccm_sdk.zm_des_block_size(); }
            // int32_t _des_ksize_min      (void) { return g_ccm_sdk.zm_des_ksize_min(); }
            // int32_t _des_ksize_max      (void) { return g_ccm_sdk.zm_des_ksize_max(); }
            // int32_t _des_ksize_multiple (void) { return g_ccm_sdk.zm_des_ksize_multiple(); }
            // int32_t _des_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_ccm_sdk.zm_des_set_ekey((des_ctx*)ctx, key, ksize); }
            // int32_t _des_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_ccm_sdk.zm_des_set_dkey((des_ctx*)ctx, key, ksize); }
            // void    _des_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_ccm_sdk.zm_des_enc_block((des_ctx*)ctx, plaintext, ciphertext); }
            // void    _des_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_ccm_sdk.zm_des_enc_block((des_ctx*)ctx, ciphertext, plaintext); }
    #endif
}

void test_case_ccm1(zmcrypto::sdk* _sdk)
{

//from rfc3610
//#   =============== packet vector #1 ==================
//#   aes key =  c0 c1 c2 c3  c4 c5 c6 c7  c8 c9 ca cb  cc cd ce cf
//#   nonce =    00 00 00 03  02 01 00 a0  a1 a2 a3 a4  a5
//#   total packet length = 31. [input with 8 cleartext header octets]
//#              00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f
//#              10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e
//#   cbc iv in: 59 00 00 00  03 02 01 00  a0 a1 a2 a3  a4 a5 00 17
//#   cbc iv out:eb 9d 55 47  73 09 55 ab  23 1e 0a 2d  fe 4b 90 d6
//#   after xor: eb 95 55 46  71 0a 51 ae  25 19 0a 2d  fe 4b 90 d6   [hdr]
//#   after aes: cd b6 41 1e  3c dc 9b 4f  5d 92 58 b6  9e e7 f0 91
//#   after xor: c5 bf 4b 15  30 d1 95 40  4d 83 4a a5  8a f2 e6 86   [msg]
//#   after aes: 9c 38 40 5e  a0 3c 1b c9  04 b5 8b 40  c7 6c a2 eb
//#   after xor: 84 21 5a 45  bc 21 05 c9  04 b5 8b 40  c7 6c a2 eb   [msg]
//#   after aes: 2d c6 97 e4  11 ca 83 a8  60 c2 c4 06  cc aa 54 2f
//#   cbc-mac  : 2d c6 97 e4  11 ca 83 a8
//#   ctr start: 01 00 00 00  03 02 01 00  a0 a1 a2 a3  a4 a5 00 01
//#   ctr[0001]: 50 85 9d 91  6d cb 6d dd  e0 77 c2 d1  d4 ec 9f 97
//#   ctr[0002]: 75 46 71 7a  c6 de 9a ff  64 0c 9c 06  de 6d 0d 8f
//#   ctr[mac ]: 3a 2e 46 c8  ec 33 a5 48
//#   total packet length = 39. [authenticated and encrypted output]
//#              00 01 02 03  04 05 06 07  58 8c 97 9a  61 c6 63 d2
//#              f0 66 d0 c2  c0 f9 89 80  6d 5f 6b 61  da c3 84 17
//#              e8 d1 2c fd  f9 26 e0

    uint8_t key[]   = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};
    uint8_t nonce[] = {0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
    uint8_t aad[]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t pt[]    = {0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e};
    uint8_t ct[]    = {0x58, 0x8c, 0x97, 0x9a, 0x61, 0xc6, 0x63, 0xd2, 0xf0, 0x66, 0xd0, 0xc2, 0xc0, 0xf9, 0x89, 0x80, 0x6d, 0x5f, 0x6b, 0x61, 0xda, 0xc3, 0x84};
    uint8_t tag[]   = {0x17, 0xe8, 0xd1, 0x2c, 0xfd, 0xf9, 0x26, 0xe0};

    uint32_t key_len   = sizeof(key);
    uint32_t nonce_len = sizeof(nonce);
    uint32_t aad_len   = sizeof(aad);
    uint32_t pt_len    = sizeof(pt);
    uint32_t ct_len    = sizeof(ct);
    uint32_t tag_len   = sizeof(tag);

    uint8_t* pt2  = (uint8_t*)malloc(pt_len);
    uint8_t* ct2  = (uint8_t*)malloc(ct_len);
    uint8_t* tag2 = (uint8_t*)malloc(tag_len);

    CONTEXT_TYPE_PTR(ccm) ctx = _sdk->zm_ccm_new();
    zmerror err;
    _sdk->zm_ccm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
    err = _sdk->zm_ccm_starts(ctx, key, key_len, nonce, nonce_len, pt_len, aad_len, tag_len, 0); printf ("ret: %08x\n", err);

    //for (int i = 0; i < aad_len; i++){
    err = _sdk->zm_ccm_update_aad(ctx, aad, aad_len); printf ("ret: %08x\n", err);//}
    err = _sdk->zm_ccm_update_data(ctx, pt, pt_len, ct2); printf ("ret: %08x\n", err);
    err = _sdk->zm_ccm_final(ctx, tag2); printf ("ret: %08x\n", err);
    _sdk->zm_ccm_free(ctx);

    printf("ct: ");
    for (uint32_t i = 0; i < ct_len; i++){
        printf ("[%02x] ", ct2[i]);
    }   printf("\n");
    printf("tag: ");
    for (uint32_t i = 0; i < tag_len; i++){
        printf ("[%02x] ", tag2[i]);
    }   printf("\n");

    free( pt2 );
    free( ct2 );
    free( tag2);
}

void test_case_ccm2(zmcrypto::sdk* _sdk)
{
    uint8_t key[]   = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    uint8_t nonce[] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c};
    uint8_t aad[]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
                        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint8_t pt[]    = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ct[]    = {0x69, 0x91, 0x5d, 0xad, 0x1e, 0x84, 0xc6, 0x37, 0x6a, 0x68, 0xc2, 0x96, 0x7e, 0x4d, 0xab, 0x61, 0x5a, 0xe0, 0xfd, 0x1f, 0xae, 0xc4, 0x4c, 0xc4, 0x84, 0x82, 0x85, 0x29, 0x46, 0x3c, 0xcf, 0x72};
    uint8_t tag[]   = {0xb4, 0xac, 0x6b, 0xec, 0x93, 0xe8, 0x59, 0x8e, 0x7f, 0x0d, 0xad, 0xbc, 0xea, 0x5b};

    uint32_t key_len   = sizeof(key);
    uint32_t nonce_len = sizeof(nonce);
    uint32_t aad_len   = sizeof(aad);
    uint32_t pt_len    = sizeof(pt);
    uint32_t ct_len    = sizeof(ct);
    uint32_t tag_len   = sizeof(tag);

    uint8_t* pt2  = (uint8_t*)malloc(pt_len);
    uint8_t* ct2  = (uint8_t*)malloc(ct_len);
    uint8_t* tag2 = (uint8_t*)malloc(tag_len);

    CONTEXT_TYPE_PTR(ccm) ctx = _sdk->zm_ccm_new();
    zmerror err;
    _sdk->zm_ccm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
    err = _sdk->zm_ccm_starts(ctx, key, key_len, nonce, nonce_len, pt_len, aad_len*256, tag_len, 0); printf ("ret: %08x\n", err);

    for (int i = 0; i < aad_len; i++){
    err = _sdk->zm_ccm_update_aad(ctx, aad, aad_len); printf ("ret: %08x\n", err);}
    err = _sdk->zm_ccm_update_data(ctx, pt, pt_len, ct2); printf ("ret: %08x\n", err);
    err = _sdk->zm_ccm_final(ctx, tag2); printf ("ret: %08x\n", err);
    _sdk->zm_ccm_free(ctx);

    printf("ct: ");
    for (uint32_t i = 0; i < ct_len; i++){
        printf ("[%02x] ", ct2[i]);
    }   printf("\n");
    printf("tag: ");
    for (uint32_t i = 0; i < tag_len; i++){
        printf ("[%02x] ", tag2[i]);
    }   printf("\n");

    free( pt2 );
    free( ct2 );
    free( tag2);
}