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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"
#include "vector_file.h"
#include "format_output.h"
#include "time_stamp.h"
#include "test_config.h"
#include "test_blowfish.h"
#include <memory.h>

#if defined TEST_FOR_CRYPTOPP
    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/modes.h"
    #include "cryptopp820/include/blowfish.h"
#endif

/* unnamed */
namespace{
    #if defined ZMCRYPTO_ALGO_BLOWFISH
        zmcrypto::sdk g_blowfish_sdk;
        void*   cb_blowfish_new            (void) { return g_blowfish_sdk.zm_blowfish_new(); }
        void    cb_blowfish_free           (void* ctx) { g_blowfish_sdk.zm_blowfish_free((blowfish_ctx*)ctx); }
        void    cb_blowfish_init           (void* ctx) { g_blowfish_sdk.zm_blowfish_init((blowfish_ctx*)ctx); }
        int32_t cb_blowfish_block_size     (void) { return g_blowfish_sdk.zm_blowfish_block_size(); }
        int32_t cb_blowfish_ksize_min      (void) { return g_blowfish_sdk.zm_blowfish_ksize_min(); }
        int32_t cb_blowfish_ksize_max      (void) { return g_blowfish_sdk.zm_blowfish_ksize_max(); }
        int32_t cb_blowfish_ksize_multiple (void) { return g_blowfish_sdk.zm_blowfish_ksize_multiple(); }
        int32_t cb_blowfish_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_blowfish_sdk.zm_blowfish_set_ekey((blowfish_ctx*)ctx, key, ksize); }
        int32_t cb_blowfish_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_blowfish_sdk.zm_blowfish_set_dkey((blowfish_ctx*)ctx, key, ksize); }
        void    cb_blowfish_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) {g_blowfish_sdk.zm_blowfish_enc_block((blowfish_ctx*)ctx, plaintext, ciphertext); }
        void    cb_blowfish_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) {g_blowfish_sdk.zm_blowfish_dec_block((blowfish_ctx*)ctx, ciphertext, plaintext); }
    #endif
}


void test_case_blowfish_ecb(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "blowfish.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_ECB && defined ZMCRYPTO_ALGO_BLOWFISH

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ecb) ctx = _sdk->zm_ecb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ecb"){
                _sdk->zm_ecb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, cb_blowfish_set_dkey, cb_blowfish_enc_block, cb_blowfish_dec_block);
            }else{
                _sdk->zm_ecb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ecb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
                err = _sdk->zm_ecb_enc (ctx, input, (uint32_t) (plaintext.size() * loop), output);
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
                    err = _sdk->zm_ecb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()), output + j * plaintext.size());
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

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ecb) ctx = _sdk->zm_ecb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ecb"){
                _sdk->zm_ecb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, cb_blowfish_set_dkey, cb_blowfish_enc_block, cb_blowfish_dec_block);
            }else{
                _sdk->zm_ecb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ecb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            err = _sdk->zm_ecb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ecb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ecb_free (ctx);

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ecb"){
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Encryption(*pCipher);
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.size() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.size(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ecb"){
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Decryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::ECB_Mode_ExternalCipher::Decryption(*pCipher);
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()));

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

void test_case_blowfish_cbc(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "blowfish.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CBC && defined ZMCRYPTO_ALGO_BLOWFISH

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cbc) ctx = _sdk->zm_cbc_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, cb_blowfish_set_dkey, cb_blowfish_enc_block, cb_blowfish_dec_block);
            }else{
                _sdk->zm_cbc_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cbc_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
                err = _sdk->zm_cbc_enc (ctx, input, (uint32_t) (plaintext.size() * loop), output);
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
                    err = _sdk->zm_cbc_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()), output + j * plaintext.size());
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

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cbc) ctx = _sdk->zm_cbc_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cbc_free (ctx);
                    return;
                }
                _sdk->zm_cbc_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, cb_blowfish_set_dkey, cb_blowfish_enc_block, cb_blowfish_dec_block);
            }else{
                _sdk->zm_cbc_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cbc_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            err = _sdk->zm_cbc_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cbc_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_cbc_free (ctx);

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.size() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.size(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-cbc"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Decryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CBC_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()));

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

void test_case_blowfish_cfb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "blowfish.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CFB && defined ZMCRYPTO_ALGO_BLOWFISH

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cfb) ctx = _sdk->zm_cfb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_cfb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cfb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }

                err = _sdk->zm_cfb_enc (ctx, input, (uint32_t) (plaintext.size() * loop), output);
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
                    err = _sdk->zm_cfb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()), output + j * plaintext.size());
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

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(cfb) ctx = _sdk->zm_cfb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_cfb_free (ctx);
                    return;
                }
                _sdk->zm_cfb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_cfb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_cfb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            err = _sdk->zm_cfb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_cfb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_cfb_free (ctx);

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.size() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.size(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-cfb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()));

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

void test_case_blowfish_ofb(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "blowfish.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_OFB && defined ZMCRYPTO_ALGO_BLOWFISH

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ofb) ctx = _sdk->zm_ofb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_ofb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ofb_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }

                err = _sdk->zm_ofb_enc (ctx, input, (uint32_t) (plaintext.size() * loop), output);
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
                    err = _sdk->zm_ofb_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()), output + j * plaintext.size());
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

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ofb) ctx = _sdk->zm_ofb_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ofb_free (ctx);
                    return;
                }
                _sdk->zm_ofb_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_ofb_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ofb_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            err = _sdk->zm_ofb_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ofb_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ofb_free (ctx);

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.size() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.size(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ofb"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::OFB_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()));

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

void test_case_blowfish_ctr(zmcrypto::sdk* _sdk)
{
#if 1
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "blowfish.txt", test_vec)){
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

        #if defined ZMCRYPTO_ALGO_CTR && defined ZMCRYPTO_ALGO_BLOWFISH

        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ctr) ctx = _sdk->zm_ctr_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_ctr_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ctr_set_ekey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                return;
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }

                err = _sdk->zm_ctr_enc (ctx, input, (uint32_t) (plaintext.size() * loop), output);
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
                    err = _sdk->zm_ctr_enc (ctx, (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()), output + j * plaintext.size());
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

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            CONTEXT_TYPE_PTR(ctr) ctx = _sdk->zm_ctr_new ();
            int32_t block_size = cb_blowfish_block_size ();
            int32_t ksize_min = cb_blowfish_ksize_min ();
            int32_t ksize_max = cb_blowfish_ksize_max ();
            int32_t ksize_multiple = cb_blowfish_ksize_multiple ();

            if (algorithm == "blowfish-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    _sdk->zm_ctr_free (ctx);
                    return;
                }
                _sdk->zm_ctr_init(ctx, cb_blowfish_new, cb_blowfish_free, cb_blowfish_init, cb_blowfish_block_size, cb_blowfish_ksize_min, cb_blowfish_ksize_max, cb_blowfish_ksize_multiple, cb_blowfish_set_ekey, /*cb_blowfish_set_dkey, */cb_blowfish_enc_block/*, cb_blowfish_dec_block*/);
            }else{
                _sdk->zm_ctr_free (ctx);
                continue;
            }

            zmerror err = _sdk->zm_ctr_set_dkey(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                return;
            }

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            err = _sdk->zm_ctr_dec (ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()), output);
            if (ZMCRYPTO_IS_ERROR(err)){
                printf ("%s\n", _sdk->zm_error_str(err));
                _sdk->zm_ctr_free (ctx);
                delete[] pt; pt = NULL;
                delete[] output; output = NULL;
                return;
            }

            _sdk->zm_ctr_free (ctx);

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Encryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Encryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* output = new uint8_t[ciphertext.size()];
            if (plaintext.size() % block_size != 0){
                uint8_t* input = new uint8_t[plaintext.size() * loop];
                for (int j = 0; j < loop; j++){
                    memcpy(input + j * plaintext.size(), plaintext.c_str(), plaintext.size());
                }
 
                pCipherMode->ProcessData(output, input, (uint32_t) (plaintext.size() * loop));
                delete[] input; input = NULL;
            }else{
                for (int j = 0; j < loop; j++){
                    pCipherMode->ProcessData(output + j * plaintext.size(), (uint8_t*) (plaintext.c_str()), (uint32_t) (plaintext.size()));
                }
            }

            if (ciphertext == std::string((char*)output, ciphertext.size())){
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

            if (loop * plaintext.size() != ciphertext.size()){
                printf ("%s\n", "The plaintext length does not match the ciphertext length");
                return;
            }

            if (algorithm == "blowfish-ctr"){
                if (iv.empty()){
                    printf("iv is empty\n");
                    return;
                }
            }else{
                continue;
            }

            /*CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Decryption();*/
            CryptoPP::BlockCipher* pCipher = new CryptoPP::Blowfish::Encryption();
            pCipher->SetKey((CryptoPP::byte*)(key.c_str()), (uint32_t)key.size());
            CryptoPP::CipherModeDocumentation::Decryption* pCipherMode = new CryptoPP::CTR_Mode_ExternalCipher::Decryption(*pCipher, (uint8_t*)iv.c_str(), (uint32_t)iv.size());
            int block_size = CryptoPP::Blowfish::BLOCKSIZE;

            uint8_t* pt = new uint8_t[plaintext.size() * loop];
            for (int j = 0; j < loop; j++){
                memcpy(pt + j * plaintext.size(), plaintext.c_str(), plaintext.size());
            }

            uint8_t* output = new uint8_t[ciphertext.size()];
            pCipherMode->ProcessData(output, (CryptoPP::byte*)(ciphertext.c_str()), (uint32_t) (ciphertext.size()));

            if (memcmp(pt, output, ciphertext.size()) == 0){
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

void test_speed_blowfish(zmcrypto::sdk* _sdk)
{
    uint8_t key[24] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    uint32_t key_sizes[3] = { 16,24,32 };
    uint8_t pt[8] = { 0 };
    uint8_t ct[8] = { 0 };

    #if defined ZMCRYPTO_ALGO_BLOWFISH
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(blowfish) ctx = _sdk->zm_blowfish_new();
            _sdk->zm_blowfish_set_ekey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_blowfish_enc_block(ctx, pt, ct);
                end = get_timestamp_us();
                dsize += _sdk->zm_blowfish_block_size();          
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_blowfish_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed * 1000;
            format_output("blowfish-%d encryption|%.2f KB/s\n", key_sizes[i]*8, rate);
        } /* for */
        for (size_t i = 0; i < sizeof(key_sizes) / sizeof(key_sizes[0]); i++)
        {
            CONTEXT_TYPE_PTR(blowfish) ctx = _sdk->zm_blowfish_new();
            _sdk->zm_blowfish_set_dkey(ctx, key, key_sizes[i]);

            uint64_t start = get_timestamp_us();
            uint64_t end = 0;
            uint64_t dsize = 0;
            while (true)
            {
                _sdk->zm_blowfish_dec_block(ctx, pt, ct);
                end = get_timestamp_us();
                dsize += _sdk->zm_blowfish_block_size();
                if (end - start >= TEST_TOTAL_SEC * 1000000){
                    break;
                }
            }
            _sdk->zm_blowfish_free(ctx);

            uint32_t elapsed = (uint32_t)(end - start);
            double rate = (double)dsize / (double)elapsed * 1000;
            format_output("blowfish-%d decryption|%.2f KB/s\n", key_sizes[i]*8, rate);
        } /* for */
    #endif
}

void test_info_blowfish(zmcrypto::sdk* _sdk)
{
#if defined ZMCRYPTO_ALGO_BLOWFISH
    int32_t blocksize = _sdk->zm_blowfish_block_size();
    int32_t min = _sdk->zm_blowfish_ksize_min();
    int32_t max = _sdk->zm_blowfish_ksize_max();
    int32_t mutiple = _sdk->zm_blowfish_ksize_multiple();

    printf ("blowfish block size: %d, min key size: %d, max key size: %d, key size multiple: %d\n",
        blocksize, min, max, mutiple);
#endif
}
