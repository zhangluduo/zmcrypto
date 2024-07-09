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
#include "test_gcm.h"

#if defined TEST_FOR_CRYPTOPP
    #include <string>
    using namespace std;

    #include "include/cryptlib.h"
    #include "include/secblock.h"
    #include "include/gcm.h"
    #include "include/aes.h"
    #include "include/filters.h"
    using namespace CryptoPP;
#endif

namespace{
    zmcrypto::sdk g_gcm_sdk;
    #if defined ZMCRYPTO_ALGO_AES       
        void*   _aes_new            (void) { return g_gcm_sdk.zm_aes_new(); }
        void    _aes_free           (void* ctx) { g_gcm_sdk.zm_aes_free((aes_ctx*)ctx); }
        void    _aes_init           (void* ctx) { g_gcm_sdk.zm_aes_init((aes_ctx*)ctx); }
        int32_t _aes_block_size     (void) { return g_gcm_sdk.zm_aes_block_size(); }
        int32_t _aes_ksize_min      (void) { return g_gcm_sdk.zm_aes_ksize_min(); }
        int32_t _aes_ksize_max      (void) { return g_gcm_sdk.zm_aes_ksize_max(); }
        int32_t _aes_ksize_multiple (void) { return g_gcm_sdk.zm_aes_ksize_multiple(); }
        int32_t _aes_set_ekey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_gcm_sdk.zm_aes_set_ekey((aes_ctx*)ctx, key, ksize); }
        int32_t _aes_set_dkey       (void* ctx, uint8_t* key, uint32_t ksize) { return g_gcm_sdk.zm_aes_set_dkey((aes_ctx*)ctx, key, ksize); }
        void    _aes_enc_block      (void* ctx, uint8_t* plaintext, uint8_t* ciphertext) { return g_gcm_sdk.zm_aes_enc_block((aes_ctx*)ctx, plaintext, ciphertext); }
        void    _aes_dec_block      (void* ctx, uint8_t* ciphertext, uint8_t* plaintext) { return g_gcm_sdk.zm_aes_enc_block((aes_ctx*)ctx, ciphertext, plaintext); }
    #endif
    #if defined ZMCRYPTO_ALGO_DES

    #endif
}

void test_case_gcm(zmcrypto::sdk* _sdk)
{
    std::vector<key_val_vec> test_vec;
    if (!read_vector_data(TEST_VECTOR_PATH "gcm.txt", test_vec)){
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

		uint32_t loop = 1;
		if (!repeat.empty()){
			loop = atoi(repeat.c_str());
		}

        #if defined ZMCRYPTO_ALGO_CCM && defined ZMCRYPTO_ALGO_AES
            /* Encryption */
            {
                zmerror err;
                uint8_t* output = NULL;
                uint8_t* tag2 = new uint8_t[tag.size()];

                if (!ciphertext.empty()){
					output = new uint8_t[plaintext.size() * loop];
					memset(output, 0, plaintext.size() * loop);
                }

                memset(tag2, 0, tag.size());
                CONTEXT_TYPE_PTR(gcm) ctx = _sdk->zm_gcm_new();
                
                if (algorithm == "aes-gcm"){
                    _sdk->zm_gcm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
                }else{
                    _sdk->zm_gcm_free (ctx);
                    /*tag and ctx memory is not released, causing memory leak*/
                    continue;
                }

                err = _sdk->zm_gcm_starts (ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size(), DO_ENCRYPT);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail;
                }

                err =_sdk->zm_gcm_update_aad (ctx, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail;
                }

				for (uint32_t i = 0; i < loop; i++){
					err = _sdk->zm_gcm_update_data(ctx, (uint8_t*)(plaintext.c_str()), (uint32_t)plaintext.length(), output + ((uint32_t)plaintext.length() * i));
					if (ZMCRYPTO_IS_ERROR(err)){
						printf("%s\n", _sdk->zm_error_str(err));
						_sdk->zm_gcm_free(ctx);
						goto fail;
					}
				}

				err = _sdk->zm_gcm_final(ctx, tag2, (uint32_t)tag.size());
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail;
                }

                _sdk->zm_gcm_free(ctx);

                if ((!ciphertext.empty() &&  ciphertext == std::string((char*)output, ciphertext.size())) ||
                    tag == std::string((char*)tag2, tag.size())){
                    format_output("%s encryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                if (output) { delete[] output; output = NULL; }
                if (tag2) { delete[] tag2; tag2 = NULL; }
                goto gcm_decrypt;

fail:

                format_output("%s encryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                if (output) { delete[] output; output = NULL; }
                if (tag2) { delete[] tag2; tag2 = NULL; }
            }
gcm_decrypt:
            /* Decryption */
            {
                zmerror err;
                uint8_t* output = NULL;
                uint8_t* tag2 = new uint8_t[tag.size()];

                if (!plaintext.empty()){
                    output = new uint8_t[plaintext.size() * loop];
					memset(output, 0, plaintext.size() * loop);
                }

                memset(tag2, 0, tag.size());
                CONTEXT_TYPE_PTR(gcm) ctx = _sdk->zm_gcm_new();
                
                if (algorithm == "aes-gcm"){
                    _sdk->zm_gcm_init (ctx, _aes_new, _aes_free, _aes_init, _aes_block_size, _aes_ksize_min, _aes_ksize_max, _aes_ksize_multiple, _aes_set_ekey, _aes_set_dkey, _aes_enc_block, _aes_dec_block);
                }else{
                    _sdk->zm_gcm_free (ctx);
                    /*tag2 and ctx memory is not released, causing memory leak*/
                    continue;
                }

                err = _sdk->zm_gcm_starts (ctx, (uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size(), DO_DECRYPT);
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail2;
                }

                err =_sdk->zm_gcm_update_aad (ctx, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail2;
                }

				err = _sdk->zm_gcm_update_data(ctx, (uint8_t*)(ciphertext.c_str()), (uint32_t)ciphertext.length(), output);
				if (ZMCRYPTO_IS_ERROR(err)){
					printf("%s\n", _sdk->zm_error_str(err));
					_sdk->zm_gcm_free(ctx);
					goto fail2;
				}

				err = _sdk->zm_gcm_final(ctx, tag2, (uint32_t)tag.size());
                if (ZMCRYPTO_IS_ERROR(err)){
                    printf ("%s\n", _sdk->zm_error_str(err));
                    _sdk->zm_gcm_free (ctx);
                    goto fail2;
                }

                _sdk->zm_gcm_free(ctx);

				if ((!plaintext.empty() && memcpy(output, plaintext.c_str(), plaintext.length()) == 0) ||
                    tag == std::string((char*)tag2, tag.size())){
                    format_output("%s decryption by ZmCrypto|%s passed\n", algorithm.c_str(), comment.c_str());
                }
                else{
                    format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                }

                if (output) { delete[] output; output = NULL; }
                if (tag2) { delete[] tag2; tag2 = NULL; }

                #if defined TEST_FOR_CRYPTOPP
                    goto cryptopp_gcm_enc;
                #else
                    continue;
                #endif
fail2:

                format_output("%s decryption by ZmCrypto|%s failed\n", algorithm.c_str(), comment.c_str());
                if (output) { delete[] output; output = NULL; }
                if (tag2) { delete[] tag2; tag2 = NULL; }
            }
        #endif

        #if defined TEST_FOR_CRYPTOPP
cryptopp_gcm_enc:
            try{
                CryptoPP::GCM<CryptoPP::AES>::Encryption e;
                e.SetKeyWithIV((uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());

                string res;
                AuthenticatedEncryptionFilter ef(e, new StringSink(res));
                ef.ChannelPut(AAD_CHANNEL, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));

				for (uint32_t i = 0; i < loop; i++){
                    ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plaintext.data(), plaintext.size());
				}   ef.ChannelMessageEnd(DEFAULT_CHANNEL);

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
            try{
                CryptoPP::GCM<CryptoPP::AES>::Decryption d;
                d.SetKeyWithIV((uint8_t*)key.c_str(), (uint32_t)key.size(), (uint8_t*)iv.c_str(), (uint32_t)iv.size());

                string res;
                AuthenticatedDecryptionFilter df( d, NULL, 
                    AuthenticatedDecryptionFilter::MAC_AT_BEGIN | 
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION );

                df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)tag.data(), tag.size());
                df.ChannelPut(AAD_CHANNEL, (uint8_t*)aad.c_str(), (uint32_t)(aad.size()));
                df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
				df.ChannelMessageEnd(DEFAULT_CHANNEL);
                
                if (df.GetLastResult()){ /* verify tag */
                    df.SetRetrievalChannel( DEFAULT_CHANNEL );
                    std::string pt;
                    int n = (size_t)df.MaxRetrievable();
                    pt.resize( n );
                    df.Get( (CryptoPP::byte*)pt.data(), n );

                    if (plaintext.size() == pt.size() / loop && memcmp(pt.c_str(), plaintext.c_str(), plaintext.size()) == 0){
                        format_output("%s decryption by Crypto++|%s passed\n", algorithm.c_str(), comment.c_str());
                    }
                    else{
                        printf ("%ld, %ld\n", plaintext.size() ,pt.size());
                        format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                    }
                }
                else{
                    format_output("%s decryption by Crypto++|%s failed\n", algorithm.c_str(), comment.c_str());
                }
            }
            catch( CryptoPP::Exception& e )
            {
                printf ("%s\n", e.what());
            }
        #endif

    } /*end for*/
}
