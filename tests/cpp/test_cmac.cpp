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
            void*   _aes_new            (void) { return g_cmac_sdk.zm_aes_new(); }
            void    _aes_free           (void* ctx) { g_cmac_sdk.zm_aes_free((aes_ctx*)ctx); }
            void    _aes_init           (void* ctx) { g_cmac_sdk.zm_aes_init((aes_ctx*)ctx); }
            int32_t _aes_block_size     (void) { return g_cmac_sdk.zm_aes_block_size(); }
            int32_t _aes_ksize_min      (void) { return g_cmac_sdk.zm_aes_ksize_min(); }
            int32_t _aes_ksize_max      (void) { return g_cmac_sdk.zm_aes_ksize_max(); }
            int32_t _aes_ksize_multiple (void) { return g_cmac_sdk.zm_aes_ksize_multiple(); }
            int32_t _aes_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); }
            int32_t _aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
            void    _aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_cmac_sdk.zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
            void    _aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_cmac_sdk.zm_aes_enc_block((aes_ctx*)ctx, ciphertext, plaintext); }
    #endif
    #if defined ZMCRYPTO_ALGO_DES

            void*   _des_new            (void) { return g_cmac_sdk.zm_des_new(); }
            void    _des_free           (void* ctx) { g_cmac_sdk.zm_des_free((des_ctx*)ctx); }
            void    _des_init           (void* ctx) { g_cmac_sdk.zm_des_init((des_ctx*)ctx); }
            int32_t _des_block_size     (void) { return g_cmac_sdk.zm_des_block_size(); }
            int32_t _des_ksize_min      (void) { return g_cmac_sdk.zm_des_ksize_min(); }
            int32_t _des_ksize_max      (void) { return g_cmac_sdk.zm_des_ksize_max(); }
            int32_t _des_ksize_multiple (void) { return g_cmac_sdk.zm_des_ksize_multiple(); }
            int32_t _des_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_des_set_ekey((des_ctx*)ctx, key, ksize); }
            int32_t _des_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_cmac_sdk.zm_des_set_dkey((des_ctx*)ctx, key, ksize); }
            void    _des_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_cmac_sdk.zm_des_enc_block((des_ctx*)ctx, plaintext, ciphertext); }
            void    _des_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_cmac_sdk.zm_des_enc_block((des_ctx*)ctx, ciphertext, plaintext); }
    #endif
}

void test_case_cmac(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "cmac.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, message, MAC, repeat;
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed: key\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "message", message)){
            printf("get key-value pair failed: message\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "MAC", MAC)){
            printf("get key-value pair failed: MAC\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_CMAC && defined ZMCRYPTO_ALGO_SHA1 && defined ZMCRYPTO_ALGO_AES
        {
            CONTEXT_TYPE_PTR(cmac) ctx = _sdk->zm_cmac_new ();
            int32_t digest_size = 0;

            if (algorithm == "cmac-aes"){
                _sdk->zm_cmac_init(ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, 
                    _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
                digest_size = _sdk->zm_cmac_digest_size(ctx);
            }
            else if (algorithm == "cmac-des"){
                _sdk->zm_cmac_init(ctx, _des_new, _des_free, _des_init, _des_block_size, _des_ksize_min, _des_ksize_max, _des_ksize_multiple, 
                    _des_set_ekey, _des_set_dkey, _des_enc_block, _des_dec_block);
                digest_size = _sdk->zm_cmac_digest_size(ctx);
            }
            else
            {
                printf ("algorithm not supports\n");
                _sdk->zm_cmac_free (ctx);
                return;
            }

            _sdk->zm_cmac_starts (ctx, (uint8_t*)key.c_str(), key.length());

            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            for (int j = 0; j < loop; j++){
                _sdk->zm_cmac_update (ctx, (uint8_t*)message.c_str(), message.length());
            }

            uint8_t* output = new uint8_t[digest_size];
            _sdk->zm_cmac_final (ctx, output);
            _sdk->zm_cmac_free (ctx);

            if (MAC == std::string((char*)output, digest_size)){
                format_output("%s by ZmCrypto|passed\n", algorithm.c_str());
            }
            else{
                format_output("%s by ZmCrypto|failed\n", algorithm.c_str());
            }

            delete[] output;
            output = NULL;
        }
        #endif
/*
        CryptoPP::CMAC<name> _mac;
        if (std::string(#name) == "RC2")
        {
            _mac.UncheckedSetKey((CryptoPP::byte*)vec_cmac_##data[i].key, vec_cmac_##data[i].key_len,
                MakeParameters(Name::EffectiveKeyLength(), (int)(vec_cmac_##data[i].key_len * 8)));
        }
        else if (std::string(#name) == "RC5")
        {
            _mac.UncheckedSetKey((CryptoPP::byte*)vec_cmac_##data[i].key, vec_cmac_##data[i].key_len,
                MakeParameters(Name::Rounds(), 12));
        }
*/
        #if defined TEST_FOR_CRYPTOPP
        {
            if (algorithm == "cmac-aes"){
                CryptoPP::CMAC<AES>* cmacPtr = new CryptoPP::CMAC<AES>;
                cmacPtr->SetKey((CryptoPP::byte*)(uint8_t*)key.c_str(), key.length());
                int loop = 1;
                if (!repeat.empty()){
                    loop = atoi(repeat.c_str());
                }

                for (int j = 0; j < loop; j++){
                    cmacPtr->Update((uint8_t*)message.c_str(), message.length());
                }

                SecByteBlock digest(cmacPtr->DigestSize());
                cmacPtr->Final (digest);

                if (MAC == std::string((char*)(CryptoPP::byte *)digest, cmacPtr->DigestSize())){
                    format_output("%s by Crypto++|passed\n", algorithm.c_str());
                }
                else{
                    format_output("%s by Crypto++|failed\n", algorithm.c_str());
                }

                delete cmacPtr;
                cmacPtr = NULL;
            }
            else if (algorithm == "cmac-des"){
                CryptoPP::CMAC<DES>* cmacPtr = new CryptoPP::CMAC<DES>;
                cmacPtr->SetKey((CryptoPP::byte*)(uint8_t*)key.c_str(), key.length());
                int loop = 1;
                if (!repeat.empty()){
                    loop = atoi(repeat.c_str());
                }

                for (int j = 0; j < loop; j++){
                    cmacPtr->Update((uint8_t*)message.c_str(), message.length());
                }

                SecByteBlock digest(cmacPtr->DigestSize());
                cmacPtr->Final (digest);

                if (MAC == std::string((char*)(CryptoPP::byte *)digest, cmacPtr->DigestSize())){
                    format_output("%s by Crypto++|passed\n", algorithm.c_str());
                }
                else{
                    format_output("%s by Crypto++|failed\n", algorithm.c_str());
                }

                delete cmacPtr;
                cmacPtr = NULL;
            }
            else
            {
                printf ("algorithm not supports\n");
                return;
            }
        }
        #endif
    }
}