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
 *   Date: Feb. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"
#include "vector_file.h"
#include "format_output.h"
#include "time_stamp.h"
#include "test_config.h"
#include "test_xtea.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/modes.h"
    // #include "include/xtea.h"
#endif

#if defined TEST_FOR_OPENSSL_SPEED
    #include <openssl/evp.h>
#endif

/* unnamed */
namespace{

    #if defined ZMCRYPTO_ALGO_XTEA
        zmcrypto::sdk g_xtea_sdk;
        void*   cb_xtea_new            (void) { return g_xtea_sdk.zm_xtea_new(); }
        void    cb_xtea_free           (void* ctx) { g_xtea_sdk.zm_xtea_free((xtea_ctx*)ctx); }
        void    cb_xtea_init           (void* ctx) { g_xtea_sdk.zm_xtea_init((xtea_ctx*)ctx); }
        int32_t cb_xtea_block_size     (void) { return g_xtea_sdk.zm_xtea_block_size(); }
        int32_t cb_xtea_ksize_min      (void) { return g_xtea_sdk.zm_xtea_ksize_min(); }
        int32_t cb_xtea_ksize_max      (void) { return g_xtea_sdk.zm_xtea_ksize_max(); }
        int32_t cb_xtea_ksize_multiple (void) { return g_xtea_sdk.zm_xtea_ksize_multiple(); }
        int32_t cb_xtea_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_xtea_sdk.zm_xtea_set_ekey((xtea_ctx*)ctx, key, ksize); }
        int32_t cb_xtea_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_xtea_sdk.zm_xtea_set_dkey((xtea_ctx*)ctx, key, ksize); }
        void    cb_xtea_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) {g_xtea_sdk.zm_xtea_enc_block((xtea_ctx*)ctx, plaintext, ciphertext); }
        void    cb_xtea_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) {g_xtea_sdk.zm_xtea_dec_block((xtea_ctx*)ctx, ciphertext, plaintext); }
    #endif
}

void test_case_xtea_ecb(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "xtea.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed: algorithm\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed: key\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed: plaintext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed: ciphertext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_ECB && defined ZMCRYPTO_ALGO_XTEA

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ecb) ctx = _sdk->zm_ecb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ecb"){
                _sdk->zm_ecb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, cb_xtea_set_dkey, cb_xtea_enc_block, cb_xtea_dec_block);
            }else{
                _sdk->zm_ecb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ecb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
                err = _sdk->zm_ecb_enc (ctx, input, (uint32_t) (plaintext.length() * loop), output);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_ecb_free (ctx);
                    delete[] input; input = NULL;
                    delete[] output; output = NULL;
                    return;
                }
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_ecb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()), output + j * plaintext.length());
                    if (ZMCRYPTO_IS_ERROR(err)){
                        printf ("%s\n", _sdk->zm_error_str(err));
                        _sdk->zm_ecb_free (ctx);
                        delete[] output;
                        output = NULL;
                        return;
                    }
                }
            }

            _sdk->zm_ecb_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ecb) ctx = _sdk->zm_ecb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ecb"){
                _sdk->zm_ecb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, cb_xtea_set_dkey, cb_xtea_enc_block, cb_xtea_dec_block);
            }else{
                _sdk->zm_ecb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ecb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            err = _sdk->zm_ecb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ecb_free (ctx);

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] pt; pt = NULL;
            delete[] output; output = NULL;
        }

        #endif

        // #if defined TEST_FOR_CRYPTOPP
        // /* Encryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ecb"){
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Encryption(*pCipher);
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     if (plaintext.length() % block_size != 0){
        //         uint8_t* input = new uint8_t[plaintext.length() * loop];
        //         for (int j = 0; j < loop; j++){
        //             memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //         }
 
        //         pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
        //         delete[] input; input = NULL;
        //     }else{
        //         for (int j = 0; j < loop; j++){
        //             pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
        //         }
        //     }

        //     if (ciphertext == std::string((char*)output, ciphertext.length())){
        //         format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }

        // /* Decryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ecb"){
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Decryption(*pCipher);
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* pt = new uint8_t[plaintext.length() * loop];
        //     for (int j = 0; j < loop; j++){
        //         memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //     }

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

        //     if (memcmp(pt, output, ciphertext.length()) == 0){
        //         format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete[] pt; pt = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }
  
        // #endif
    }
}

void test_case_xtea_cbc(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "xtea.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_CBC && defined ZMCRYPTO_ALGO_XTEA

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cbc) ctx = _sdk->zm_cbc_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, cb_xtea_set_dkey, cb_xtea_enc_block, cb_xtea_dec_block);
            }else{
                _sdk->zm_cbc_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cbc_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
                err = _sdk->zm_cbc_enc (ctx, input, (uint32_t) (plaintext.length() * loop), output);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_cbc_free (ctx);
                    delete[] input; input = NULL;
                    delete[] output; output = NULL;
                    return;
                }
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_cbc_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()), output + j * plaintext.length());
                    if (ZMCRYPTO_IS_ERROR(err)){
                        printf ("%s\n", _sdk->zm_error_str(err));
                        _sdk->zm_cbc_free (ctx);
                        delete[] output;
                        output = NULL;
                        return;
                    }
                }
            }

            _sdk->zm_cbc_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cbc) ctx = _sdk->zm_cbc_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, cb_xtea_set_dkey, cb_xtea_enc_block, cb_xtea_dec_block);
            }else{
                _sdk->zm_cbc_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cbc_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            err = _sdk->zm_cbc_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_cbc_free (ctx);

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] pt; pt = NULL;
            delete[] output; output = NULL;
        }

        #endif

        // #if defined TEST_FOR_CRYPTOPP
        // /* Encryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-cbc"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     if (plaintext.length() % block_size != 0){
        //         uint8_t* input = new uint8_t[plaintext.length() * loop];
        //         for (int j = 0; j < loop; j++){
        //             memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //         }
 
        //         pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
        //         delete[] input; input = NULL;
        //     }else{
        //         for (int j = 0; j < loop; j++){
        //             pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
        //         }
        //     }

        //     if (ciphertext == std::string((char*)output, ciphertext.length())){
        //         format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }

        // /* Decryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-cbc"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* pt = new uint8_t[plaintext.length() * loop];
        //     for (int j = 0; j < loop; j++){
        //         memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //     }

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

        //     if (memcmp(pt, output, ciphertext.length()) == 0){
        //         format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete[] pt; pt = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }
  
        // #endif
    }
#endif
}

void test_case_xtea_cfb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "xtea.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_CFB && defined ZMCRYPTO_ALGO_XTEA

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cfb) ctx = _sdk->zm_cfb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_cfb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cfb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }

                err = _sdk->zm_cfb_enc (ctx, input, (uint32_t) (plaintext.length() * loop), output);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_cfb_free (ctx);
                    delete[] input; input = NULL;
                    delete[] output; output = NULL;
                    return;
                }
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_cfb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()), output + j * plaintext.length());
                    if (ZMCRYPTO_IS_ERROR(err)){
                        printf ("%s\n", _sdk->zm_error_str(err));
                        _sdk->zm_cfb_free (ctx);
                        delete[] output;
                        output = NULL;
                        return;
                    }
                }
            }

            _sdk->zm_cfb_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cfb) ctx = _sdk->zm_cfb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_cfb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cfb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            err = _sdk->zm_cfb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_cfb_free (ctx);

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] pt; pt = NULL;
            delete[] output; output = NULL;
        }

        #endif

        // #if defined TEST_FOR_CRYPTOPP
        // /* Encryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-cfb"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     if (plaintext.length() % block_size != 0){
        //         uint8_t* input = new uint8_t[plaintext.length() * loop];
        //         for (int j = 0; j < loop; j++){
        //             memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //         }
 
        //         pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
        //         delete[] input; input = NULL;
        //     }else{
        //         for (int j = 0; j < loop; j++){
        //             pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
        //         }
        //     }

        //     if (ciphertext == std::string((char*)output, ciphertext.length())){
        //         format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }

        // /* Decryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-cfb"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     /*CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();*/
        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* pt = new uint8_t[plaintext.length() * loop];
        //     for (int j = 0; j < loop; j++){
        //         memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //     }

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

        //     if (memcmp(pt, output, ciphertext.length()) == 0){
        //         format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete[] pt; pt = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }
  
        // #endif
    }
#endif
}

void test_case_xtea_ofb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "xtea.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_OFB && defined ZMCRYPTO_ALGO_XTEA

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ofb) ctx = _sdk->zm_ofb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_ofb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ofb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }

                err = _sdk->zm_ofb_enc (ctx, input, (uint32_t) (plaintext.length() * loop), output);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_ofb_free (ctx);
                    delete[] input; input = NULL;
                    delete[] output; output = NULL;
                    return;
                }
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_ofb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()), output + j * plaintext.length());
                    if (ZMCRYPTO_IS_ERROR(err)){
                        printf ("%s\n", _sdk->zm_error_str(err));
                        _sdk->zm_ofb_free (ctx);
                        delete[] output;
                        output = NULL;
                        return;
                    }
                }
            }

            _sdk->zm_ofb_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ofb) ctx = _sdk->zm_ofb_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_ofb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ofb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            err = _sdk->zm_ofb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ofb_free (ctx);

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] pt; pt = NULL;
            delete[] output; output = NULL;
        }

        #endif

        // #if defined TEST_FOR_CRYPTOPP
        // /* Encryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ofb"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     if (plaintext.length() % block_size != 0){
        //         uint8_t* input = new uint8_t[plaintext.length() * loop];
        //         for (int j = 0; j < loop; j++){
        //             memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //         }
 
        //         pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
        //         delete[] input; input = NULL;
        //     }else{
        //         for (int j = 0; j < loop; j++){
        //             pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
        //         }
        //     }

        //     if (ciphertext == std::string((char*)output, ciphertext.length())){
        //         format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }

        // /* Decryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ofb"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     /*CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();*/
        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* pt = new uint8_t[plaintext.length() * loop];
        //     for (int j = 0; j < loop; j++){
        //         memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //     }

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

        //     if (memcmp(pt, output, ciphertext.length()) == 0){
        //         format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete[] pt; pt = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }
  
        // #endif
    }
#endif
}

void test_case_xtea_ctr(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "xtea.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, plaintext, ciphertext, repeat, comment;
        if (!get_key_val_pair(test_vec, i, "comment", comment)){
        }
        if (!get_key_val_pair(test_vec, i, "algorithm", algorithm)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "key", key)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "iv", iv)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_CTR && defined ZMCRYPTO_ALGO_XTEA

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ctr) ctx = _sdk->zm_ctr_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_ctr_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ctr_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }

                err = _sdk->zm_ctr_enc (ctx, input, (uint32_t) (plaintext.length() * loop), output);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_ctr_free (ctx);
                    delete[] input; input = NULL;
                    delete[] output; output = NULL;
                    return;
                }
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_ctr_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()), output + j * plaintext.length());
                    if (ZMCRYPTO_IS_ERROR(err)){
                        printf ("%s\n", _sdk->zm_error_str(err));
                        _sdk->zm_ctr_free (ctx);
                        delete[] output;
                        output = NULL;
                        return;
                    }
                }
            }

            _sdk->zm_ctr_free (ctx);

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output;
            output = NULL;
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.length() != ciphertext.length()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ctr) ctx = _sdk->zm_ctr_new ();
            int32_t block_size = cb_xtea_block_size ();
            int32_t ksize_min = cb_xtea_ksize_min ();
            int32_t ksize_max = cb_xtea_ksize_max ();
            int32_t ksize_multiple = cb_xtea_ksize_multiple ();

            if (algorithm == "xtea-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_xtea_new, cb_xtea_free, cb_xtea_init, cb_xtea_block_size, cb_xtea_ksize_min, cb_xtea_ksize_max, cb_xtea_ksize_multiple, cb_xtea_set_ekey, /*cb_xtea_set_dkey, */cb_xtea_enc_block/*, cb_xtea_dec_block*/);
            }else{
                _sdk->zm_ctr_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ctr_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.length(), (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            err = _sdk->zm_ctr_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ctr_free (ctx);

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
            }
            delete[] pt; pt = NULL;
            delete[] output; output = NULL;
        }

        #endif

        // #if defined TEST_FOR_CRYPTOPP
        // /* Encryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ctr"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     if (plaintext.length() % block_size != 0){
        //         uint8_t* input = new uint8_t[plaintext.length() * loop];
        //         for (int j = 0; j < loop; j++){
        //             memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //         }
 
        //         pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
        //         delete[] input; input = NULL;
        //     }else{
        //         for (int j = 0; j < loop; j++){
        //             pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
        //         }
        //     }

        //     if (ciphertext == std::string((char*)output, ciphertext.length())){
        //         format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }

        // /* Decryption */
        // {
        //     int loop = 1;
        //     if (!repeat.empty()){
        //         loop = atoi(repeat.c_str());
        //     }

        //     if (loop * plaintext.length() != ciphertext.length()){
        //         printf ("%s\n", "The plaintext length does not match the ciphertext length");
        //         return;
        //     }

        //     if (algorithm == "xtea-ctr"){
        //         if (iv.empty()){
        //             printf("iv is empty\n");
        //             return;
        //         }
        //     }else{
        //         continue;
        //     }

        //     /*CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();*/
        //     CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
        //     pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
        //     CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
        //     int block_size = CryptoPP::XTEA::BLOCKSIZE;

        //     uint8_t* pt = new uint8_t[plaintext.length() * loop];
        //     for (int j = 0; j < loop; j++){
        //         memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
        //     }

        //     uint8_t* output = new uint8_t[ciphertext.length()];
        //     pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

        //     if (memcmp(pt, output, ciphertext.length()) == 0){
        //         format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
        //     }
        //     else{
        //         format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
        //     }

        //     delete[] output; output = NULL;
        //     delete[] pt; pt = NULL;
        //     delete pCipher; pCipher = NULL;
        //     delete pCipherMode; pCipherMode = NULL;
        // }
  
        // #endif
    }
#endif
}

void test_speed_xtea(zmcrypto::sdk* _sdk)
{
    uint8_t key[24] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint32_t key_sizes[1] = { 16 };
    uint8_t in[16] = { 0 };
    uint8_t out[16] = { 0 };

    #if defined ZMCRYPTO_ALGO_XTEA
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(xtea) ctx = _sdk->zm_xtea_new();
            _sdk->zm_xtea_set_ekey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_xtea_enc_block(ctx, in, out);
                end = get_timestamp_us();
                dsize += _sdk->zm_xtea_block_size();          
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_xtea_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("xtea encryption by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(xtea) ctx = _sdk->zm_xtea_new();
            _sdk->zm_xtea_set_dkey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_xtea_dec_block(ctx, in, out);
                end = get_timestamp_us();
                dsize += _sdk->zm_xtea_block_size();
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_xtea_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("xtea decryption by zmcrypto|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
    #endif

    // #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
    //     for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    //     {
    //         CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Encryption();
    //         pCipher->SetKey(key, key_sizes[i]);

    //         uint64_t start = get_timestamp_us();
    //         uint64_t end = 0;
    //         uint64_t dsize = 0;
    //         while (true)
    //         {
    //             pCipher->ProcessBlock(in, out);
                
    //             end = get_timestamp_us();
    //             dsize += 16;
    //             if (end - start >= TEST_TOTAL_SEC * 1000000){
    //                 break;
    //             }
    //         }

    //         uint32_t elapsed = (uint32_t)(end - start);
    //         double rate = (double)dsize / (double)elapsed;
    //         format_output("xtea encryption by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
    //         delete pCipher;
    //         pCipher = NULL;
    //     } /* for */
    //     for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    //     {
    //         CryptoPP::BlockCipher* pCipher = new CryptoPP::XTEA::Decryption();
    //         pCipher->SetKey(key, key_sizes[i]);

    //         uint64_t start = get_timestamp_us();
    //         uint64_t end = 0;
    //         uint64_t dsize = 0;
    //         while (true)
    //         {
    //             pCipher->ProcessBlock(in, out);
                
    //             end = get_timestamp_us();
    //             dsize += 16;
    //             if (end - start >= TEST_TOTAL_SEC * 1000000){
    //                 break;
    //             }
    //         }

    //         uint32_t elapsed = (uint32_t)(end - start);
    //         double rate = (double)dsize / (double)elapsed;
    //         format_output("xtea encryption by Crypto++|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
    //         delete pCipher;
    //         pCipher = NULL;
    //     } /* for */
    // #endif 

    // #if defined TEST_FOR_OPENSSL_SPEED
    //     int ilen = 16;
    //     int olen = 16;
    //     for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    //     {
    //         const EVP_CIPHER *cipher = EVP_xtea_ecb();
    //         EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    //         EVP_EncryptInit(ctx, cipher, key, NULL);

    //         uint64_t start = get_timestamp_us();
    //         uint64_t end = 0;
    //         uint64_t dsize = 0;
    //         while (true)
    //         {
    //             ilen = 16;
    //             olen = 16;
    //             EVP_EncryptUpdate(ctx, in, &olen, out, ilen);
                
    //             end = get_timestamp_us();
    //             dsize += 16;
    //             if (end - start >= TEST_TOTAL_SEC * 1000000){
    //                 break;
    //             }
    //         }
    //         EVP_EncryptFinal(ctx, out, &olen);
    //         EVP_CIPHER_CTX_free(ctx);

    //         uint32_t elapsed = (uint32_t)(end - start);
    //         double rate = (double)dsize / (double)elapsed;
    //         format_output("xtea encryption by OpenSSL|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
    //     } /* for */
    //     for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    //     for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
    //     {
    //         const EVP_CIPHER *cipher = EVP_xtea_ecb();
    //         EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    //         EVP_EncryptInit(ctx, cipher, key, NULL);

    //         uint64_t start = get_timestamp_us();
    //         uint64_t end = 0;
    //         uint64_t dsize = 0;
    //         while (true)
    //         {
    //             ilen = 16;
    //             olen = 16;
    //             EVP_DecryptUpdate(ctx, in, &olen, out, ilen);
                
    //             end = get_timestamp_us();
    //             dsize += 16;
    //             if (end - start >= TEST_TOTAL_SEC * 1000000){
    //                 break;
    //             }
    //         }
    //         EVP_DecryptFinal(ctx, out, &olen);
    //         EVP_CIPHER_CTX_free(ctx);

    //         uint32_t elapsed = (uint32_t)(end - start);
    //         double rate = (double)dsize / (double)elapsed;
    //         format_output("xtea decryption by OpenSSL|%s/s\n", bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
    //     } /* for */
    // #endif
}

void test_info_xtea(zmcrypto::sdk* _sdk)
{
#if defined ZMCRYPTO_ALGO_XTEA
    int32_t blocksize = _sdk->zm_xtea_block_size();
    int32_t min = _sdk->zm_xtea_ksize_min();
    int32_t max = _sdk->zm_xtea_ksize_max();
    int32_t mutiple = _sdk->zm_xtea_ksize_multiple();

    printf ("xtea block size: %d, min key size: %d, max key size: %d, key size multiple: %d\n",
        blocksize, min, max, mutiple);
#endif
}
