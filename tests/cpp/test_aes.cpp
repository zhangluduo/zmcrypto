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
#include "test_aes.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/modes.h"
    #include "include/aes.h"
#endif

#if defined TEST_FOR_OPENSSL_SPEED
    #include <openssl/aes.h>
#endif

#if defined TEST_FOR_MBEDTLS_SPEED
    #include <mbedtls/aes.h>
#endif

/* unnamed */
namespace{

    #if defined ZMCRYPTO_ALGO_AES
        zmcrypto::sdk g_aes_sdk;
        void*   cb_aes_new            (void) { return g_aes_sdk.zm_aes_new(); }
        void    cb_aes_free           (void* ctx) { g_aes_sdk.zm_aes_free((aes_ctx*)ctx); }
        void    cb_aes_init           (void* ctx) { g_aes_sdk.zm_aes_init((aes_ctx*)ctx); }
        int32_t cb_aes_block_size     (void) { return g_aes_sdk.zm_aes_block_size(); }
        int32_t cb_aes_ksize_min      (void) { return g_aes_sdk.zm_aes_ksize_min(); }
        int32_t cb_aes_ksize_max      (void) { return g_aes_sdk.zm_aes_ksize_max(); }
        int32_t cb_aes_ksize_multiple (void) { return g_aes_sdk.zm_aes_ksize_multiple(); }
        int32_t cb_aes_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_aes_sdk.zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); }
        int32_t cb_aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_aes_sdk.zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
        void    cb_aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) {g_aes_sdk.zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
        void    cb_aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) {g_aes_sdk.zm_aes_dec_block((aes_ctx*)ctx, ciphertext, plaintext); }
    #endif
}

void test_case_aes_ecb(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_ECB && defined ZMCRYPTO_ALGO_AES

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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ecb"){
                _sdk->zm_ecb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, cb_aes_set_dkey, cb_aes_enc_block, cb_aes_dec_block);
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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ecb"){
                _sdk->zm_ecb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, cb_aes_set_dkey, cb_aes_enc_block, cb_aes_dec_block);
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

        #if defined TEST_FOR_CRYPTOPP
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

            if (algorithm == "aes-ecb"){
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Encryption(*pCipher);
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
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

            if (algorithm == "aes-ecb"){
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Decryption(*pCipher);
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete[] pt; pt = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
        }
  
        #endif
    }
}

void test_case_aes_cbc(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CBC && defined ZMCRYPTO_ALGO_AES

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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, cb_aes_set_dkey, cb_aes_enc_block, cb_aes_dec_block);
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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, cb_aes_set_dkey, cb_aes_enc_block, cb_aes_dec_block);
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

        #if defined TEST_FOR_CRYPTOPP
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

            if (algorithm == "aes-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
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

            if (algorithm == "aes-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete[] pt; pt = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
        }
  
        #endif
    }
#endif
}

void test_case_aes_cfb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CFB && defined ZMCRYPTO_ALGO_AES

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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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

        #if defined TEST_FOR_CRYPTOPP
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

            if (algorithm == "aes-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
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

            if (algorithm == "aes-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete[] pt; pt = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
        }
  
        #endif
    }
#endif
}

void test_case_aes_ofb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_OFB && defined ZMCRYPTO_ALGO_AES

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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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

        #if defined TEST_FOR_CRYPTOPP
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

            if (algorithm == "aes-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
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

            if (algorithm == "aes-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete[] pt; pt = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
        }
  
        #endif
    }
#endif
}

void test_case_aes_ctr(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "aes.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CTR && defined ZMCRYPTO_ALGO_AES

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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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
            int32_t block_size = cb_aes_block_size ();
            int32_t ksize_min = cb_aes_ksize_min ();
            int32_t ksize_max = cb_aes_ksize_max ();
            int32_t ksize_multiple = cb_aes_ksize_multiple ();

            if (algorithm == "aes-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_aes_new, cb_aes_free, cb_aes_init, cb_aes_block_size, cb_aes_ksize_min, cb_aes_ksize_max, cb_aes_ksize_multiple, cb_aes_set_ekey, /*cb_aes_set_dkey, */cb_aes_enc_block/*, cb_aes_dec_block*/);
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

        #if defined TEST_FOR_CRYPTOPP
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

            if (algorithm == "aes-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.length()];
            if (plaintext.length() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.length() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.length(), plaintext.c_str(), plaintext.length());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.length() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.length(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.length()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.length())){
                format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
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

            if (algorithm == "aes-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.length());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.length());
            int block_size = CryptoPP::AES::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.length() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.length(), plaintext.c_str(), plaintext.length());
            }

            uint8_t* output = new uint8_t[ciphertext.length()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.length()));

            if (memcmp(pt, output, ciphertext.length()) == 0){
                format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
            }
            else{
                format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
            }

            delete[] output; output = NULL;
            delete[] pt; pt = NULL;
            delete pCipher; pCipher = NULL;
            delete pCipherMode; pCipherMode = NULL;
        }
  
        #endif
    }
#endif
}

void test_speed_aes(zmcrypto::sdk* _sdk)
{
    uint8_t key[24] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint32_t key_sizes[3] = { 16,24,32 };
    uint8_t in[16] = { 0 };
    uint8_t out[16] = { 0 };

    #if defined ZMCRYPTO_ALGO_AES
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(aes) ctx = _sdk->zm_aes_new();
            _sdk->zm_aes_set_ekey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_aes_enc_block(ctx, in, out);
                end = get_timestamp_us();
                dsize += _sdk->zm_aes_block_size();          
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_aes_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d encryption by ZmCrypto|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate * 1000000)).c_str());
            
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(aes) ctx = _sdk->zm_aes_new();
            _sdk->zm_aes_set_dkey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_aes_dec_block(ctx, in, out);
                end = get_timestamp_us();
                dsize += _sdk->zm_aes_block_size();
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_aes_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d decryption by ZmCrypto|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
    #endif

    #if defined TEST_FOR_CRYPTOPP && defined TEST_FOR_CRYPTOPP_SPEED
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Encryption();
            pCipher->SetKey(key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                pCipher->ProcessBlock(in, out);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d encryption by Crypto++|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
            delete pCipher;
            pCipher = NULL;
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CryptoPP::BlockCipher* pCipher = new CryptoPP::AES::Decryption();
            pCipher->SetKey(key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                pCipher->ProcessBlock(in, out);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d decryption by Crypto++|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
            delete pCipher;
            pCipher = NULL;
        } /* for */
    #endif 

    #if defined TEST_FOR_OPENSSL_SPEED
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            AES_KEY aesKey;
            AES_set_encrypt_key(key, key_sizes[i] * 8, &aesKey);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                AES_encrypt(in, out, &aesKey);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d encryption by OpenSSL|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            AES_KEY aesKey;
            AES_set_decrypt_key(key, key_sizes[i] * 8, &aesKey);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                AES_decrypt(in, out, &aesKey);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d decryption by OpenSSL|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
    #endif

    #if defined TEST_FOR_MBEDTLS_SPEED
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_enc(&ctx, key, key_sizes[i] * 8);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d encryption by mbedTLS|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            mbedtls_aes_context ctx;
            mbedtls_aes_init(&ctx);
            mbedtls_aes_setkey_dec(&ctx, key, key_sizes[i] * 8);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, in, out);
                
                end = get_timestamp_us();
                dsize += 16;
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed;
            format_output("aes-%d decryption by mbedTLS|%s/s\n", key_sizes[i]*8, bytes_to_human_readable_format((uint64_t)(rate*1000000)).c_str());
        } /* for */
    #endif 
}

void test_info_aes(zmcrypto::sdk* _sdk)
{
#if defined ZMCRYPTO_ALGO_AES
    int32_t blocksize = _sdk->zm_aes_block_size();
    int32_t min = _sdk->zm_aes_ksize_min();
    int32_t max = _sdk->zm_aes_ksize_max();
    int32_t mutiple = _sdk->zm_aes_ksize_multiple();

    printf ("aes block size: %d, min key size: %d, max key size: %d, key size multiple: %d\n",
        blocksize, min, max, mutiple);
#endif
}
