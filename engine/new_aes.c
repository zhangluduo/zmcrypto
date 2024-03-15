/**
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
 *         https://github.com/zhangluduo/zmcrypto/
 */

 /**
 * Reference: 
 *     [Announcing the ADVANCED ENCRYPTION STANDARD (AES)]
 *     https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 */

#include "new_aes.h"

void print_data(char* title, uint8_t* data, uint32_t dlen){
    printf ("%s", title);
    for (uint32_t i = 0; i < dlen; i++){
        printf("%02x ", data[i]);
    }
}

aes_ctx* aes_new2 (void)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    pfn_aes_new _pfn_aes_new  = zm_get_orig_fnc("zm_aes_new");
    if (_pfn_aes_new){
        return _pfn_aes_new();
    }

    return NULL;
}

void aes_free2 (aes_ctx* ctx)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    pfn_aes_free _pfn_aes_free  = zm_get_orig_fnc("zm_aes_free");
    if (_pfn_aes_free){
        _pfn_aes_free(ctx);
    }
}

void aes_init2 (aes_ctx* ctx)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    pfn_aes_init _pfn_aes_init  = zm_get_orig_fnc("zm_aes_init");
    if (_pfn_aes_init){
        _pfn_aes_init(ctx);
    }
}

int32_t aes_block_size2 (void)
    { 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    return 16; }

int32_t aes_ksize_min2 (void)
    { 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    return 16; }

int32_t aes_ksize_max2 (void)
    { 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    return 32; }

int32_t aes_ksize_multiple2 (void)
    { 
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    return 8; }

int32_t aes_set_ekey2 (aes_ctx* ctx, uint8_t* key, uint32_t ksize)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    pfn_aes_set_ekey _pfn_aes_set_key  = zm_get_orig_fnc("zm_aes_set_ekey");
    if (_pfn_aes_set_key){
        return _pfn_aes_set_key(ctx, key, ksize);
    }

    return ZMCRYPTO_ERR_NULL_PTR;
}

zmerror aes_set_dkey2 (aes_ctx* ctx, uint8_t* key, uint32_t ksize)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    print_data("key: ", key, ksize);
    printf ("\n");
    pfn_aes_set_dkey _pfn_aes_set_key  = zm_get_orig_fnc("zm_aes_set_dkey");
    if (_pfn_aes_set_key){
        return _pfn_aes_set_key(ctx, key, ksize);
    }
    return ZMCRYPTO_ERR_NULL_PTR;
}

void aes_enc_block2 (aes_ctx* ctx, uint8_t* plaintext, uint8_t* ciphertext)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    print_data("plaintext: ", plaintext, 16);
    printf ("\n");
    pfn_aes_enc_block _pfn_aes_enc_block  = zm_get_orig_fnc("zm_aes_enc_block");
    if (_pfn_aes_enc_block){
        _pfn_aes_enc_block(ctx, plaintext, ciphertext);
    }
}

void aes_dec_block2 (aes_ctx* ctx, uint8_t* ciphertext, uint8_t* plaintext)
{
    printf("%s:%d %s\n", __FILE__, __LINE__, __FUNCTION__);
    print_data("ciphertext: ", ciphertext, 16);
    printf ("\n");
    pfn_aes_dec_block _pfn_aes_dec_block  = zm_get_orig_fnc("zm_aes_dec_block");
    if (_pfn_aes_dec_block){
        _pfn_aes_dec_block(ctx, ciphertext, plaintext);
    }
}
