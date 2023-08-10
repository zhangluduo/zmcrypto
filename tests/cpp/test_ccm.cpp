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
    zmcrypto::sdk g_cmac_sdk;
    #if defined ZMCRYPTO_ALGO_AES       
            // void*   _aes_new            (void) { return g_cmac_sdk.zm_aes_new(); }
            // void    _aes_free           (void* ctx) { g_cmac_sdk.zm_aes_free((aes_ctx*)ctx); }
            // void    _aes_init           (void* ctx) { g_cmac_sdk.zm_aes_init((aes_ctx*)ctx); }
            // int32_t _aes_block_size     (void) { return g_cmac_sdk.zm_aes_block_size(); }
            // int32_t _aes_ksize_min      (void) { return g_cmac_sdk.zm_aes_ksize_min(); }
            // int32_t _aes_ksize_max      (void) { return g_cmac_sdk.zm_aes_ksize_max(); }
            // int32_t _aes_ksize_multiple (void) { return g_cmac_sdk.zm_aes_ksize_multiple(); }
            // int32_t _aes_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); }
            // int32_t _aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
            // void    _aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_cmac_sdk.zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
            // void    _aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_cmac_sdk.zm_aes_enc_block((aes_ctx*)ctx, ciphertext, plaintext); }
    #endif
    #if defined ZMCRYPTO_ALGO_DES
            // void*   _des_new            (void) { return g_cmac_sdk.zm_des_new(); }
            // void    _des_free           (void* ctx) { g_cmac_sdk.zm_des_free((des_ctx*)ctx); }
            // void    _des_init           (void* ctx) { g_cmac_sdk.zm_des_init((des_ctx*)ctx); }
            // int32_t _des_block_size     (void) { return g_cmac_sdk.zm_des_block_size(); }
            // int32_t _des_ksize_min      (void) { return g_cmac_sdk.zm_des_ksize_min(); }
            // int32_t _des_ksize_max      (void) { return g_cmac_sdk.zm_des_ksize_max(); }
            // int32_t _des_ksize_multiple (void) { return g_cmac_sdk.zm_des_ksize_multiple(); }
            // int32_t _des_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_des_set_ekey((des_ctx*)ctx, key, ksize); }
            // int32_t _des_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_des_set_dkey((des_ctx*)ctx, key, ksize); }
            // void    _des_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_cmac_sdk.zm_des_enc_block((des_ctx*)ctx, plaintext, ciphertext); }
            // void    _des_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_cmac_sdk.zm_des_enc_block((des_ctx*)ctx, ciphertext, plaintext); }
    #endif
}

void test_case_ccm(zmcrypto::sdk* _sdk)
{
}