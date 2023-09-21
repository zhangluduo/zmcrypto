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
    #include <string>
    using namespace std;

    #include "cryptopp820/include/cryptlib.h"
    #include "cryptopp820/include/secblock.h"
    #include "cryptopp820/include/ccm.h"
    #include "cryptopp820/include/aes.h"
    #include "cryptopp820/include/filters.h"
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

    #endif
}

#if defined TEST_FOR_CRYPTOPP
     template <class T_BlockCipher, bool T_IsEncryption>
     class CCM_Final2 : public CCM_Base
     {
     public:
         static std::string StaticAlgorithmName()
             {return T_BlockCipher::StaticAlgorithmName() + std::string("/CCM");}
         bool IsForwardTransformation() const
             {return T_IsEncryption;}

        void SetDigestSize(int n){
            m_digestSize = n;
        }
  
     private:
         BlockCipher & AccessBlockCipher() {return m_cipher;}
         int DefaultDigestSize() const {return m_digestSize;}
         typename T_BlockCipher::Encryption m_cipher;
     };

    template <class T_BlockCipher>
    struct CCM2 : public AuthenticatedSymmetricCipherDocumentation
    {
        typedef CCM_Final2<T_BlockCipher, true> Encryption;
        typedef CCM_Final2<T_BlockCipher, false> Decryption;
    };
#endif

void test_case_ccm(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "ccm.txt", test_vec)){
        printf("read test vector data failed\n");
        return;
    }

    for (size_t i = 0; i < test_vec.size(); i++){
        std::string algorithm, key, iv, aad, repeat, plaintext, ciphertext, tag, comment;
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
            printf("get key-value pair failed: iv\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "aad", aad)){
        }
        if (!get_key_val_pair(test_vec, i, "plaintext", plaintext)){
            printf("get key-value pair failed: plaintext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "ciphertext", ciphertext)){
            printf("get key-value pair failed: ciphertext\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "tag", tag)){
            printf("get key-value pair failed: tag\n");
            return;
        }
        if (!get_key_val_pair(test_vec, i, "repeat", repeat)){
        }

        #if defined ZMCRYPTO_ALGO_CCM && defined ZMCRYPTO_ALGO_AES
            /* Encryption */
            {
                int loop = 1;
                if (!repeat.empty()){
                    loop = atoi(repeat.c_str());
                }

                zmerror err;
                uint8_t* output = new uint8_t[ciphertext.size()];
                uint8_t* tag2 = new uint8_t[tag.size()];
                memset(output, 0, ciphertext.size());
                memset(tag2, 0, tag.size());
                CONTEXT_TYPE_PTR(ccm) ctx = _sdk->zm_ccm_new();
                
                if (algorithm == "aes-ccm"){
                    _sdk->zm_ccm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
                }else{
                    _sdk->zm_ccm_free (ctx);
                    continue;
                }
                
                err = _sdk->zm_ccm_starts(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)(iv.c_str()), 
                    (uint32_t)iv.size(), (uint32_t)plaintext.size(), (uint32_t)(aad.size() * loop), (uint32_t)tag.size(), 0); 
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_ccm_free (ctx);
                    return;
                }

                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_ccm_update_aad(ctx, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));
                }
                err = _sdk->zm_ccm_update_data(ctx, (uint8_t*)plaintext.c_str(), (uint32_t)plaintext.size(), output); 

                /*
                Only a small part of the plaintext is updated
                for (int i = 0; i < plaintext.size(); i++){
                    err = _sdk->zm_ccm_update_data(ctx, (uint8_t*)(plaintext.c_str() + i), 1, output + i); 
                }
                */
                err = _sdk->zm_ccm_final(ctx, tag2); 
                _sdk->zm_ccm_free(ctx);

                if (ciphertext == std::string((char*)output, ciphertext.size()) &&
                    tag == std::string((char*)tag2, tag.size())){
                    format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                delete[] output; output = NULL;
                delete[] tag2; tag2 = NULL;
            }
            /* Decryption */
            {
                int loop = 1;
                if (!repeat.empty()){
                    loop = atoi(repeat.c_str());
                }

                zmerror err;
                uint8_t* output = new uint8_t[ciphertext.size()];
                uint8_t* tag2 = new uint8_t[tag.size()];
                CONTEXT_TYPE_PTR(ccm) ctx = _sdk->zm_ccm_new();
                
                if (algorithm == "aes-ccm"){
                    _sdk->zm_ccm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
                }else{
                    _sdk->zm_ccm_free (ctx);
                    continue;
                }
                
                err = _sdk->zm_ccm_starts(ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)(iv.c_str()), 
                    (uint32_t)iv.size(), (uint32_t)plaintext.size(), (uint32_t)(aad.size() * loop), (uint32_t)tag.size(), 1); 
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_ccm_free (ctx);
                    return;
                }

                for (int j = 0; j < loop; j++){
                    err = _sdk->zm_ccm_update_aad(ctx, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));
                }
                err = _sdk->zm_ccm_update_data(ctx, (uint8_t*)ciphertext.c_str(), (uint32_t)ciphertext.size(), output); 

                err = _sdk->zm_ccm_final(ctx, tag2); 
                _sdk->zm_ccm_free(ctx);

                if (plaintext == std::string((char*)output, plaintext.size()) &&
                    tag == std::string((char*)tag2, tag.size())){
                    format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                delete[] output; output = NULL;
                delete[] tag2; tag2 = NULL;
            }
        #endif

        #if defined TEST_FOR_CRYPTOPP
        /* Encryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            try
            {
                CCM2<AES/*, tag size */>::Encryption e;
                e.SetDigestSize(tag.size());
                
                e.SetKeyWithIV((uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
                e.SpecifyDataLengths( aad.size() * loop, plaintext.size(), 0);

                string res;
                AuthenticatedEncryptionFilter ef(e, new StringSink(res));

                for (uint32_t j = 0; j < loop; j++){
                    ef.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size()); }
                ef.ChannelMessageEnd(AAD_CHANNEL);

                ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);

                if (ciphertext.size() + tag.size() == res.size()){
                    if (memcmp(res.c_str(), ciphertext.c_str(), ciphertext.size()) == 0 &&
                    memcmp(res.c_str() + ciphertext.size(), tag.c_str(), tag.size()) == 0){
                        format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                    }
                    else{
                        format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                    }
                }
                else{
                    format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }
            }
            catch( CryptoPP::Exception& e )
            {
                printf ("%s\n", e.what());
            }
        }

        /* Decryption */
        {
            int loop = 1;
            if (!repeat.empty()){
                loop = atoi(repeat.c_str());
            }

            try
            {
                CCM2<AES/*, tag size */>::Decryption d;
                d.SetDigestSize(tag.size());
                d.SetKeyWithIV((uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());
                d.SpecifyDataLengths(aad.size() * loop, ciphertext.length(), 0);

                string res;
                AuthenticatedDecryptionFilter df( d, NULL, 
                    AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION );

                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)tag.data(), tag.size());
                for (uint32_t j = 0; j < loop; j++){
                    df.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());}
                df.ChannelMessageEnd(AAD_CHANNEL);

                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.length());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);

                /* If the object does not throw, here's the only opportunity to check the data's integrity */
                if (df.GetLastResult()){ /* verify tag */

                    df.SetRetrievalChannel( DEFAULT_CHANNEL );
                    std::string pt;
                    int n = (size_t)df.MaxRetrievable();
                    pt.resize( n );
                    df.Get( (byte*)pt.data(), n );

                    if (plaintext.size() == pt.size() && memcmp(pt.c_str(), plaintext.c_str(), plaintext.size()) == 0){
                        format_output("%s encryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                    }
                    else{
                        format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                    }
                }
                else{
                    format_output("%s encryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }
            }
            catch( CryptoPP::Exception& e )
            {
                printf ("%s\n", e.what());
            }
        }
        #endif
    }
}
