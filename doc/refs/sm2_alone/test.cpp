
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stddef.h>
#include <inttypes.h>

#include "sm2.h"
#include "sm3.h"
#include "log.h"

#define _VERIFY_INI_OPENSSL 1

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
#include <openssl/evp.h>
#include <openssl/engine.h>
#endif

const char* sm2_pri_key_pem = 
    "-----BEGIN EC PARAMETERS-----\n"
    "BggqgRzPVQGCLQ==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIAQ0xydNJvTwfX7oyNdMSX8C0iHZ5RYXSbqrUSx8ppKEoAoGCCqBHM9V\n"
    "AYItoUQDQgAECsdfVNAOWuHPTgso2I+c7e7GvrjjUQrc783Dw3FFaQlQ8DtzEB14\n"
    "RLggNrwJCjIzYSce39ImYW7hSQmJAX6qkw==\n"
    "-----END EC PRIVATE KEY-----\n";
// 00000000h: 30 77 02 01 01 04 20 04 34 C7 27 4D 26 F4 F0 7D ; 
// 00000010h: 7E E8 C8 D7 4C 49 7F 02 D2 21 D9 E5 16 17 49 BA ; 
// 00000020h: AB 51 2C 7C A6 92 84 A0 0A 06 08 2A 81 1C CF 55 ; 
// 00000030h: 01 82 2D A1 44 03 42 00 04 0A C7 5F 54 D0 0E 5A ; 
// 00000040h: E1 CF 4E 0B 28 D8 8F 9C ED EE C6 BE B8 E3 51 0A ; 
// 00000050h: DC EF CD C3 C3 71 45 69 09 50 F0 3B 73 10 1D 78 ; 
// 00000060h: 44 B8 20 36 BC 09 0A 32 33 61 27 1E DF D2 26 61 ; 
// 00000070h: 6E E1 49 09 89 01 7E AA 93                      ; 
//   0 119: SEQUENCE {
//   2   1:   INTEGER 1
//   5  32:   OCTET STRING
//        :     04 34 C7 27 4D 26 F4 F0 7D 7E E8 C8 D7 4C 49 7F
//        :     02 D2 21 D9 E5 16 17 49 BA AB 51 2C 7C A6 92 84
//  39  10:   [0] {
//  41   8:     OBJECT IDENTIFIER '1 2 156 10197 1 301'
//        :     }
//  51  68:   [1] {
//  53  66:     BIT STRING
//        :       04 [0A C7 5F 54 D0 0E 5A E1 CF 4E 0B 28 D8 8F 9C
//        :       ED EE C6 BE B8 E3 51 0A DC EF CD C3 C3 71 45 69
//        :       09 50 F0 3B 73 10 1D 78 44 B8 20 36 BC 09 0A 32
//        :       33 61 27 1E DF D2 26 61 6E E1 49 09 89 01 7E AA
//        :       93]
//        :     }
//        :   }
// 0 warnings, 0 errors.

const char* sm2_pub_key_pem = 
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAECsdfVNAOWuHPTgso2I+c7e7Gvrjj\n"
    "UQrc783Dw3FFaQlQ8DtzEB14RLggNrwJCjIzYSce39ImYW7hSQmJAX6qkw==\n"
    "-----END PUBLIC KEY-----\n";
// 00000000h: 30 59 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A ;
// 00000010h: 81 1C CF 55 01 82 2D 03 42 00 04 0A C7 5F 54 D0 ;
// 00000020h: 0E 5A E1 CF 4E 0B 28 D8 8F 9C ED EE C6 BE B8 E3 ;
// 00000030h: 51 0A DC EF CD C3 C3 71 45 69 09 50 F0 3B 73 10 ;
// 00000040h: 1D 78 44 B8 20 36 BC 09 0A 32 33 61 27 1E DF D2 ;
// 00000050h: 26 61 6E E1 49 09 89 01 7E AA 93                ;
//   0  89: SEQUENCE {
//   2  19:   SEQUENCE {
//   4   7:     OBJECT IDENTIFIER '1 2 840 10045 2 1'
//  13   8:     OBJECT IDENTIFIER '1 2 156 10197 1 301'
//        :     }
//  23  66:   BIT STRING
//        :     04 0A C7 5F 54 D0 0E 5A E1 CF 4E 0B 28 D8 8F 9C
//        :     ED EE C6 BE B8 E3 51 0A DC EF CD C3 C3 71 45 69
//        :     09 50 F0 3B 73 10 1D 78 44 B8 20 36 BC 09 0A 32
//        :     33 61 27 1E DF D2 26 61 6E E1 49 09 89 01 7E AA
//        :     93
//        :   }
// 0 warnings, 0 errors.

    unsigned char sm2_raw_public_x[32] = { 0x0a, 0xc7, 0x5f, 0x54, 0xd0, 0x0e, 0x5a, 0xe1, 0xcf, 0x4e, 0x0b, 0x28, 0xd8, 0x8f, 0x9c, 0xed, 0xee, 0xc6, 0xbe, 0xb8, 0xe3, 0x51, 0x0a, 0xdc, 0xef, 0xcd, 0xc3, 0xc3, 0x71, 0x45, 0x69, 0x09 };
    unsigned char sm2_raw_public_y[32] = { 0x50, 0xf0, 0x3b, 0x73, 0x10, 0x1d, 0x78, 0x44, 0xb8, 0x20, 0x36, 0xbc, 0x09, 0x0a, 0x32, 0x33, 0x61, 0x27, 0x1e, 0xdf, 0xd2, 0x26, 0x61, 0x6e, 0xe1, 0x49, 0x09, 0x89, 0x01, 0x7e, 0xaa, 0x93 };
    unsigned char sm2_raw_private[32]  = { 0x04, 0x34, 0xc7, 0x27, 0x4d, 0x26, 0xf4, 0xf0, 0x7d, 0x7e, 0xe8, 0xc8, 0xd7, 0x4c, 0x49, 0x7f, 0x02, 0xd2, 0x21, 0xd9, 0xe5, 0x16, 0x17, 0x49, 0xba, 0xab, 0x51, 0x2c, 0x7c, 0xa6, 0x92, 0x84 };


/* "1234567812345678" */
unsigned char sm2_id[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
unsigned int sm2_id_len = sizeof(sm2_id);

int _sm2_rand(void *rng_state, unsigned char *output, size_t len)
{
    for(size_t i = 0; i < len; ++i)
        output[i] = rand();
    return 0;
}

void print_bytes(unsigned char* data, int len){
    for (int i = 0; i < len; i++){
        printf ("%02x ", data[i]);
    }   printf ("\n");
}

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
static EC_KEY *get_sm2_pri_key(void)
{
    int ret ;
    BIO *bio = BIO_new_mem_buf(sm2_pri_key_pem, (int)strlen(sm2_pri_key_pem));
    if (NULL == bio){
        printf("[ERROR] bio is null \n");
		return NULL;
    }
    EC_KEY * ecKey = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return ecKey;
}

static EC_KEY *get_sm2_pub_key(void)
{
    BIO *bio = BIO_new_mem_buf(sm2_pub_key_pem, (int)strlen(sm2_pub_key_pem));
    if (NULL == bio){
        printf("[ERROR] bio is null \n");
		return NULL;
    }
    EC_KEY * ecKey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
	return ecKey;
}

int test_evp_sm2_veri(unsigned char* sig, int siglen)
{
    int ret;

    {
        EC_KEY *ecKey = NULL;
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EVP_MD* md = NULL;
        EVP_MD_CTX* mdctx = NULL;

        ecKey = get_sm2_pub_key();
        if (!ecKey){
            LOG("failed");
            goto fail2;
        }

        /* EVP_PKEY and EVP_PKEY_CTX */
        pkey = EVP_PKEY_new();
        if (!pkey){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_set1_EC_KEY(pkey, ecKey); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }
        ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }

        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx){
            LOG("failed");
            goto fail2;
        }

        /* EVP_MD and EVP_MD_CTX */
        mdctx = EVP_MD_CTX_new();
        md = (EVP_MD*)EVP_get_digestbyname("sm3");//EVP_sm3();
        if (!md || !mdctx){
            LOG("failed");
            goto fail2;
        }

        EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);

        /* id must be configured */
        if ( EVP_PKEY_CTX_set1_id(pctx, sm2_id, sm2_id_len) <= 0 )
        {
            LOG("failed");
            goto fail2;
        }

        if (EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, pkey) <= 0) {
            LOG("EVP_DigestSignInit failed");
            goto fail2;
        }

        if (EVP_DigestVerifyUpdate(mdctx, "helloworld", 10) <= 0) {
            LOG("EVP_DigestSignUpdate failed");
            goto fail2;
        }

        if (EVP_DigestVerifyFinal(mdctx, sig, siglen) <= 0) {
            LOG("verify failed");
            goto fail2;
        }

        LOG("verify successed");
        if (ecKey) { EC_KEY_free(ecKey); }
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (mdctx) { EVP_MD_CTX_destroy(mdctx); }
        /*if (md) EVP_MD_meth_free((EVP_MD*)md);  //double free or corruption (out) */
        LOG("successed");
        return 1;
fail2:
        if (ecKey) { EC_KEY_free(ecKey); }
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (mdctx) { EVP_MD_CTX_destroy(mdctx); }
        /*if (md) EVP_MD_meth_free((EVP_MD*)md);  //double free or corruption (out) */
        LOG("failed");
        return 0;
    }
}

int test_evp_sm2_dec(unsigned char* ct, unsigned int ctlen){

    unsigned char pt[200];
    size_t ptlen = 200;
    int ret = 0;

    /* decrypt */
    {
        EC_KEY *ecKey = NULL;
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_CTX* pctx = NULL;

        ecKey = get_sm2_pri_key();
        if (!ecKey){
            LOG("failed");
            goto fail2;
        }

        /* EVP_PKEY and EVP_PKEY_CTX */
        pkey = EVP_PKEY_new();
        if (!pkey){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_set1_EC_KEY(pkey, ecKey); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }
        ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }

        pctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pctx){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_decrypt_init(pctx);
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_decrypt(pctx, pt, &ptlen, (const unsigned char*)ct, ctlen);
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }

        printf ("pt(openssl): ");
        for (size_t i = 0; i < ptlen; i++){
            printf ("%02x ", pt[i]);
        }   printf ("\n");

        if (ecKey) { EC_KEY_free(ecKey); }
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        LOG("successed");
        return 1;

fail2:
        LOG("failed");
        return 1;
    }

    return 0;
}
#endif

void* _sm3_create() { return (new sm3_context()); }
void  _sm3_free(void* ctx) { if (ctx) { delete ((sm3_context*)ctx); ctx = NULL;} }
void  _sm3_init(void* ctx) { memset(ctx, 0, sizeof(sm3_context)); }
void  _sm3_starts(void* ctx) { sm3_starts((sm3_context*)ctx); }
void  _sm3_update(void* ctx, unsigned char* data, uint32_t len) { sm3_update((sm3_context*)ctx, data, len); }
void  _sm3_finish(void* ctx, unsigned char* output) { sm3_finish((sm3_context*)ctx, output); }

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ valgrind ./test 
==1831999== Memcheck, a memory error detector
==1831999== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1831999== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1831999== Command: ./test
==1831999== 
sig:    r = aa 43 19 67 3e cc 0c 85 09 df 77 7b 4c 53 9b 19 a6 31 cd ac 97 85 fe a2 5c 67 f8 e6 58 e8 08 77 
        s = 0c d1 11 7a 29 b2 c9 68 60 8c 75 55 2f fc 0b b5 64 74 e3 88 fa eb bb 29 26 d5 f7 7e 28 c9 63 7b 
sig(der): 30 45 02 21 00 aa 43 19 67 3e cc 0c 85 09 df 77 7b 4c 53 9b 19 a6 31 cd ac 97 85 fe a2 5c 67 f8 e6 58 e8 08 77 02 20 0c d1 11 7a 29 b2 c9 68 60 8c 75 55 2f fc 0b b5 64 74 e3 88 fa eb bb 29 26 d5 f7 7e 28 c9 63 7b 
sig2:   r = aa 43 19 67 3e cc 0c 85 09 df 77 7b 4c 53 9b 19 a6 31 cd ac 97 85 fe a2 5c 67 f8 e6 58 e8 08 77 
        s = 0c d1 11 7a 29 b2 c9 68 60 8c 75 55 2f fc 0b b5 64 74 e3 88 fa eb bb 29 26 d5 f7 7e 28 c9 63 7b 
[BEANPOD][2022-10-31T15:58:49+0800][1831999] /home/zhangluduo/Documents/test_gmssl_sm2_alone/test.cpp, int test_evp_sm2_veri(unsigned char*, int):194 verify successed
[BEANPOD][2022-10-31T15:58:49+0800][1831999] /home/zhangluduo/Documents/test_gmssl_sm2_alone/test.cpp, int test_evp_sm2_veri(unsigned char*, int):200 successed
verify successed
successed
==1831999== 
==1831999== HEAP SUMMARY:
==1831999==     in use at exit: 0 bytes in 0 blocks
==1831999==   total heap usage: 3,045 allocs, 3,045 frees, 202,127 bytes allocated
==1831999== 
==1831999== All heap blocks were freed -- no leaks are possible
==1831999== 
==1831999== For lists of detected and suppressed errors, rerun with: -s
==1831999== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ 
*/
int test_sm2_sig_veri(){
    printf ("------------------------------------- \n");
    int ret = 0;

    SM2_SIGNATURE signature;
    sm2_init_signature(&signature);

    SM2_KEY sm2_key;
    sm2_init_key(&sm2_key);

    SM3_FN sm3_fn;
    sm3_fn.create = _sm3_create;
    sm3_fn.free   = _sm3_free;
    sm3_fn.init   = _sm3_init;
    sm3_fn.starts = _sm3_starts;
    sm3_fn.update = _sm3_update;
    sm3_fn.finish = _sm3_finish;

    unsigned char sm2_raw_public_x[32] = { 0x0a, 0xc7, 0x5f, 0x54, 0xd0, 0x0e, 0x5a, 0xe1, 0xcf, 0x4e, 0x0b, 0x28, 0xd8, 0x8f, 0x9c, 0xed, 0xee, 0xc6, 0xbe, 0xb8, 0xe3, 0x51, 0x0a, 0xdc, 0xef, 0xcd, 0xc3, 0xc3, 0x71, 0x45, 0x69, 0x09 };
    unsigned char sm2_raw_public_y[32] = { 0x50, 0xf0, 0x3b, 0x73, 0x10, 0x1d, 0x78, 0x44, 0xb8, 0x20, 0x36, 0xbc, 0x09, 0x0a, 0x32, 0x33, 0x61, 0x27, 0x1e, 0xdf, 0xd2, 0x26, 0x61, 0x6e, 0xe1, 0x49, 0x09, 0x89, 0x01, 0x7e, 0xaa, 0x93 };
    unsigned char sm2_raw_private[32] = { 0x04, 0x34, 0xc7, 0x27, 0x4d, 0x26, 0xf4, 0xf0, 0x7d, 0x7e, 0xe8, 0xc8, 0xd7, 0x4c, 0x49, 0x7f, 0x02, 0xd2, 0x21, 0xd9, 0xe5, 0x16, 0x17, 0x49, 0xba, 0xab, 0x51, 0x2c, 0x7c, 0xa6, 0x92, 0x84 };

    memcpy(sm2_key.public_key.x, sm2_raw_public_x, 32);
    memcpy(sm2_key.public_key.y, sm2_raw_public_y, 32);
    memcpy(sm2_key.private_key, sm2_raw_private, 32);

    {
        SM2_SIGN_CTX sig_ctx;
        sm2_init_sign_ctx(&sig_ctx);

        if (sm2_sign_init(&sig_ctx, &sm2_key, sm3_fn, "1234567812345678", 16) <= 0){
            printf("failed\n");
            return -1;
        }
        if (sm2_sign_update(&sig_ctx, (uint8_t*)"helloworld", 10) <= 0){
            printf ("failed\n");
            return -2;
        }
        
        memset(&signature, 0, sizeof(SM2_SIGNATURE));
        if (sm2_sign_finish(&sig_ctx, _sm2_rand, NULL, &signature) <= 0){
            printf ("failed\n");
            return -3;
        }

        printf ("sig: "); 
        printf ("\tr = "); print_bytes(signature.r, 32);
        printf ("\ts = "); print_bytes(signature.s, 32);

        unsigned char* der_out = NULL;
        uint32_t der_len = 0;
        if (sm2_encode_signagure_to_der(&signature, &der_out, &der_len) <= 0){
            printf ("encode to der failed");
        }
        else{
            printf ("sig(der): "); print_bytes(der_out, der_len);

            {/* test decode DER */
                SM2_SIGNATURE sig2;
                if (sm2_decode_signagure_from_der(der_out, der_len, &sig2) == 1)
                {
                    printf ("sig2: "); 
                    printf ("\tr = "); print_bytes(sig2.r, 32);
                    printf ("\ts = "); print_bytes(sig2.s, 32);
                }
            }
        }

        #if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
            (void)test_evp_sm2_veri(der_out, der_len);
            /* MAKE BAD SIGNATURE */
            // unsigned char ch = der_out[0];
            // /*der_out[0] = 0x00;
            // (void)test_evp_sm2_veri(der_out, der_len);
            // der_out[0] = ch; /* restore */
        #endif

        sm2_encode_signagure_to_der_free(&der_out);
    }
    {
        SM2_SIGN_CTX verify_ctx;
        sm2_init_sign_ctx(&verify_ctx);

        if (sm2_verify_init(&verify_ctx, &sm2_key, sm3_fn, "1234567812345678", 16) <= 0){
            printf("failed\n");
            return -1;
        }
        if (sm2_verify_update(&verify_ctx, (uint8_t*)"helloworld", 10) <= 0){
            printf ("failed\n");
            return -2;
        }
        
        if ((ret = sm2_verify_finish(&verify_ctx, &signature)) <= 0){
            printf ("verify failed [%d]\n", ret);
            return -3;
        }
        printf ("verify successed\n");
    }
    // {
    //     SM2_SIGN_CTX sig_ctx;
    //     sm2_init_sign_ctx(&sig_ctx);
    //     if (sm2_verify_init(&sig_ctx, &sm2_key, sm3_fn, "1234567812345678", 16) <= 0){
    //         printf("failed\n");
    //         return -1;
    //     }
    //     if (sm2_verify_update(&sig_ctx, (uint8_t*)"helloworld", 10) <= 0){
    //         printf ("failed\n");
    //         return -2;
    //     }
        
    //     /* bad signagure */
    //     signature.r[0] = 0x00;
    //     signature.s[0] = 0x00;
    //     if ((ret = sm2_verify_finish(&sig_ctx, &signature)) <= 0){
    //         printf ("verify failed\n", ret);
    //         return -3;
    //     }
    //     printf ("verify successed\n");
    // }
    return 1;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ valgrind ./test 
==1832316== Memcheck, a memory error detector
==1832316== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1832316== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1832316== Command: ./test
==1832316== 
cipher result: 
        x: 76 70 f4 6e b5 0c eb 4d 33 ad c6 fb 68 6d 62 a2 c6 03 e1 e6 3d 72 8e b9 40 e9 93 bd d2 73 86 33 
        y: 98 b6 02 85 fa 80 23 1d be cd 35 9b fa 3e 7c 13 b9 52 4e 14 5c 1b c7 ee a7 fb 76 79 11 1d f0 3e 
        digest: 0c 80 ec c6 c0 51 9f 68 85 1b 8a 76 0c 35 cc 19 52 f0 c7 69 cc f7 22 2a 59 bd 6d 69 52 d9 b3 0e 
        ct: 0b 0d 83 4a b2 ae 0d 34 03 57 
cipher text(der): 30 73 02 20 76 70 f4 6e b5 0c eb 4d 33 ad c6 fb 68 6d 62 a2 c6 03 e1 e6 3d 72 8e b9 40 e9 93 bd d2 73 86 33 02 21 00 98 b6 02 85 fa 80 23 1d be cd 35 9b fa 3e 7c 13 b9 52 4e 14 5c 1b c7 ee a7 fb 76 79 11 1d f0 3e 04 20 0c 80 ec c6 c0 51 9f 68 85 1b 8a 76 0c 35 cc 19 52 f0 c7 69 cc f7 22 2a 59 bd 6d 69 52 d9 b3 0e 04 0a 0b 0d 83 4a b2 ae 0d 34 03 57 
pt(openssl): 68 65 6c 6c 6f 77 6f 72 6c 64 
[BEANPOD][2022-10-31T15:59:35+0800][1832316] /home/zhangluduo/Documents/test_gmssl_sm2_alone/test.cpp, int test_evp_sm2_dec(unsigned char*, unsigned int):275 successed
plain text: 
68 65 6c 6c 6f 77 6f 72 6c 64 
successed
==1832316== 
==1832316== HEAP SUMMARY:
==1832316==     in use at exit: 0 bytes in 0 blocks
==1832316==   total heap usage: 369 allocs, 369 frees, 103,068 bytes allocated
==1832316== 
==1832316== All heap blocks were freed -- no leaks are possible
==1832316== 
==1832316== For lists of detected and suppressed errors, rerun with: -s
==1832316== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ 
*/
int test_sm2_enc_dec(){
    printf ("------------------------------------- \n");
    SM2_KEY sm2_key;
    sm2_init_key(&sm2_key);

    SM3_FN fn;
    fn.create = _sm3_create;
    fn.free   = _sm3_free;
    fn.init   = _sm3_init;
    fn.starts = _sm3_starts;
    fn.update = _sm3_update;
    fn.finish = _sm3_finish;

    unsigned char sm2_raw_public_x[32] = { 0x0a, 0xc7, 0x5f, 0x54, 0xd0, 0x0e, 0x5a, 0xe1, 0xcf, 0x4e, 0x0b, 0x28, 0xd8, 0x8f, 0x9c, 0xed, 0xee, 0xc6, 0xbe, 0xb8, 0xe3, 0x51, 0x0a, 0xdc, 0xef, 0xcd, 0xc3, 0xc3, 0x71, 0x45, 0x69, 0x09 };
    unsigned char sm2_raw_public_y[32] = { 0x50, 0xf0, 0x3b, 0x73, 0x10, 0x1d, 0x78, 0x44, 0xb8, 0x20, 0x36, 0xbc, 0x09, 0x0a, 0x32, 0x33, 0x61, 0x27, 0x1e, 0xdf, 0xd2, 0x26, 0x61, 0x6e, 0xe1, 0x49, 0x09, 0x89, 0x01, 0x7e, 0xaa, 0x93 };
    unsigned char sm2_raw_private[32] = { 0x04, 0x34, 0xc7, 0x27, 0x4d, 0x26, 0xf4, 0xf0, 0x7d, 0x7e, 0xe8, 0xc8, 0xd7, 0x4c, 0x49, 0x7f, 0x02, 0xd2, 0x21, 0xd9, 0xe5, 0x16, 0x17, 0x49, 0xba, 0xab, 0x51, 0x2c, 0x7c, 0xa6, 0x92, 0x84 };

    memcpy(sm2_key.public_key.x, sm2_raw_public_x, 32);
    memcpy(sm2_key.public_key.y, sm2_raw_public_y, 32);
    memcpy(sm2_key.private_key, sm2_raw_private, 32);

    SM2_CIPHERTEXT output;
    sm2_init_ciphertext(&output);

    {
        if (sm2_encrypt(&sm2_key, fn, _sm2_rand, NULL, (uint8_t*)"helloworld", 10, &output) <= 0){
            printf ("failed\n");
            return -1;
        }

        printf("cipher result: \n");
        printf("\tx: "); print_bytes(output.point.x, 32);
        printf("\ty: "); print_bytes(output.point.y, 32);
        printf("\tdigest: "); print_bytes(output.digest, 32);
        printf("\tct: "); print_bytes(output.ciphertext, output.ciphertext_size);

        unsigned char* der_out = NULL;
        uint32_t der_len = 0;
        if (sm2_encode_cipher_to_der(&output, e_sm2_c1c3c2, &der_out, &der_len) == 1)
        {
            printf ("cipher text(der): ");
            print_bytes (der_out, der_len);

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
            test_evp_sm2_dec(der_out, der_len);
#endif           
        }
        sm2_encode_cipher_to_der_free(&der_out);
    }

    {
        uint8_t pt[1024];
        size_t ptlen = 1024;
        if (sm2_decrypt(&sm2_key, fn, &output, pt, &ptlen) <= 0){
            printf ("failed\n");
            return -2;
        }
        printf("plain text: \n");
        print_bytes(pt, ptlen);
    }

    // {/* make bad cipher text */
    //     uint8_t pt[1024];
    //     size_t ptlen = 1024;
    //     output.ciphertext[0] = 0xff;
    //     output.ciphertext[1] = 0x00;
    //     if (sm2_decrypt(&sm2_key, &output, pt, &ptlen) <= 0){
    //         printf ("failed\n");
    //         return -3;
    //     }
    //     printf("plain text: \n");
    //     print_bytes(pt, ptlen);
    // }

    return 1;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ valgrind ./test 
==1831234== Memcheck, a memory error detector
==1831234== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1831234== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1831234== Command: ./test
==1831234== 
public-x: cf a0 88 96 32 b2 d2 c0 15 3c 95 8b 33 0e f9 23 65 b3 72 e9 f2 8a 03 05 e4 92 84 42 99 d7 59 55 
public-y: fd d1 b6 9b 75 4d 48 c9 e6 99 29 df 52 bc 72 d8 7d 23 60 53 00 97 2d 62 ee fe 5b 8e b7 25 00 b8 
private: 9d 75 67 ce 36 e7 a8 13 1e bd 88 80 86 03 fd 7c 84 ff b9 fa 8d c5 7b 8c c2 40 fe ce 03 b9 4b 9f 
successed
==1831234== 
==1831234== HEAP SUMMARY:
==1831234==     in use at exit: 0 bytes in 0 blocks
==1831234==   total heap usage: 4 allocs, 4 frees, 78,296 bytes allocated
==1831234== 
==1831234== All heap blocks were freed -- no leaks are possible
==1831234== 
==1831234== For lists of detected and suppressed errors, rerun with: -s
==1831234== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ 
*/

int test_sm2_gen_key()
{
    printf ("------------------------------------- \n");
    SM2_KEY key;
    sm2_init_key(&key);

    if (sm2_key_generate(_sm2_rand, NULL, &key) <= 0){
        printf ("failed\n");
        return -1;
    }
    printf ("public-x: "); print_bytes(key.public_key.x, 32);
    printf ("public-y: "); print_bytes(key.public_key.y, 32);
    printf ("private: "); print_bytes(key.private_key, 32);

    memset(key.public_key.y, 0, 32);
    if (sm2_key_decompress(&key, 0x02) != 1){
        if (sm2_key_decompress(&key, 0x03) != 1){
            return -1;
        }
    }

    printf ("public-x: "); print_bytes(key.public_key.x, 32);
    printf ("public-y: "); print_bytes(key.public_key.y, 32);

    return 1;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ valgrind ./test 
==1832577== Memcheck, a memory error detector
==1832577== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1832577== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1832577== Command: ./test
==1832577== 
ret: 1
point.x: f3 13 43 d7 11 28 43 3a 9d b4 df 79 ea e9 5c 4f 97 a3 fa 26 3b e7 f6 63 aa 00 c2 4d cc d4 29 39 
point.y: b2 57 d1 18 ef cb a8 27 73 3f 23 ee e7 16 ae 8c 10 45 1d c3 64 b1 a9 cb 07 67 c8 f0 a5 5a 92 49 
digest: 8d 1b b6 0f ec e2 62 20 fb 25 d3 2f 1e fb 69 e8 79 f6 b6 9d 15 a4 ab 83 aa 37 dc 15 6f 79 ca 8f 
cipher text: 94 eb a8 b9 bb 76 2c 2c 25 49 
ret: 1
point.x: f3 13 43 d7 11 28 43 3a 9d b4 df 79 ea e9 5c 4f 97 a3 fa 26 3b e7 f6 63 aa 00 c2 4d cc d4 29 39 
point.y: b2 57 d1 18 ef cb a8 27 73 3f 23 ee e7 16 ae 8c 10 45 1d c3 64 b1 a9 cb 07 67 c8 f0 a5 5a 92 49 
digest: 8d 1b b6 0f ec e2 62 20 fb 25 d3 2f 1e fb 69 e8 79 f6 b6 9d 15 a4 ab 83 aa 37 dc 15 6f 79 ca 8f 
cipher text: 94 eb a8 b9 bb 76 2c 2c 25 49 
successed
==1832577== 
==1832577== HEAP SUMMARY:
==1832577==     in use at exit: 0 bytes in 0 blocks
==1832577==   total heap usage: 2 allocs, 2 frees, 73,728 bytes allocated
==1832577== 
==1832577== All heap blocks were freed -- no leaks are possible
==1832577== 
==1832577== For lists of detected and suppressed errors, rerun with: -s
==1832577== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/test_gmssl_sm2_alone$ 
*/
int test_der_encode_decode()
{
    printf ("------------------------------------- \n");
    int ret = 0;
    /*c1c2c3*/
    {
    unsigned char der[118] = {
        0x30, 0x74, 
        0x02, 0x21, 
        0x00, 0xf3, 0x13, 0x43, 0xd7, 0x11, 0x28, 0x43, 0x3a, 0x9d, 0xb4, 0xdf, 0x79, 0xea, 0xe9, 0x5c, 0x4f, 0x97, 0xa3, 0xfa, 0x26, 0x3b, 0xe7, 0xf6, 0x63, 0xaa, 0x00, 0xc2, 0x4d, 0xcc, 0xd4, 0x29, 0x39, 
        0x02, 0x21, 
        0x00, 0xb2, 0x57, 0xd1, 0x18, 0xef, 0xcb, 0xa8, 0x27, 0x73, 0x3f, 0x23, 0xee, 0xe7, 0x16, 0xae, 0x8c, 0x10, 0x45, 0x1d, 0xc3, 0x64, 0xb1, 0xa9, 0xcb, 0x07, 0x67, 0xc8, 0xf0, 0xa5, 0x5a, 0x92, 0x49, 
        0x04, 0x20, 
        0x8d, 0x1b, 0xb6, 0xf, 0xec, 0xe2, 0x62, 0x20, 0xfb, 0x25, 0xd3, 0x2f, 0x1e, 0xfb, 0x69, 0xe8, 0x79, 0xf6, 0xb6, 0x9d, 0x15, 0xa4, 0xab, 0x83, 0xaa, 0x37, 0xdc, 0x15, 0x6f, 0x79, 0xca, 0x8f, 
        0x04, 0x0a, 
        0x94, 0xeb, 0xa8, 0xb9, 0xbb, 0x76, 0x2c, 0x2c, 0x25, 0x49
        };

        SM2_CIPHERTEXT out;
        sm2_init_ciphertext(&out);

        ret = sm2_decode_cipher_from_der(der, 118, e_sm2_c1c2c3, &out);
        printf ("ret: %d\n", ret);
        if (ret == 1){
            printf ("point.x: "); print_bytes(out.point.x, 32);
            printf ("point.y: "); print_bytes(out.point.y, 32);
            printf ("digest: "); print_bytes(out.digest, 32);
            printf ("cipher text: "); print_bytes(out.ciphertext, out.ciphertext_size);
        }
        else{
            return ret;
        }
    }
    /*c1c3c2*/
    {
    unsigned char der[118] = {
        0x30, 0x74, 
        0x02, 0x21, 
        0x00, 0xf3, 0x13, 0x43, 0xd7, 0x11, 0x28, 0x43, 0x3a, 0x9d, 0xb4, 0xdf, 0x79, 0xea, 0xe9, 0x5c, 0x4f, 0x97, 0xa3, 0xfa, 0x26, 0x3b, 0xe7, 0xf6, 0x63, 0xaa, 0x00, 0xc2, 0x4d, 0xcc, 0xd4, 0x29, 0x39, 
        0x02, 0x21, 
        0x00, 0xb2, 0x57, 0xd1, 0x18, 0xef, 0xcb, 0xa8, 0x27, 0x73, 0x3f, 0x23, 0xee, 0xe7, 0x16, 0xae, 0x8c, 0x10, 0x45, 0x1d, 0xc3, 0x64, 0xb1, 0xa9, 0xcb, 0x07, 0x67, 0xc8, 0xf0, 0xa5, 0x5a, 0x92, 0x49, 
        0x04, 0x0a, 
        0x94, 0xeb, 0xa8, 0xb9, 0xbb, 0x76, 0x2c, 0x2c, 0x25, 0x49,
        0x04, 0x20, 
        0x8d, 0x1b, 0xb6, 0xf, 0xec, 0xe2, 0x62, 0x20, 0xfb, 0x25, 0xd3, 0x2f, 0x1e, 0xfb, 0x69, 0xe8, 0x79, 0xf6, 0xb6, 0x9d, 0x15, 0xa4, 0xab, 0x83, 0xaa, 0x37, 0xdc, 0x15, 0x6f, 0x79, 0xca, 0x8f, 
        };

        SM2_CIPHERTEXT out;
        sm2_init_ciphertext(&out);

        ret = sm2_decode_cipher_from_der(der, 118, e_sm2_c1c3c2, &out);
        printf ("ret: %d\n", ret);
        if (ret == 1){
            printf ("point.x: "); print_bytes(out.point.x, 32);
            printf ("point.y: "); print_bytes(out.point.y, 32);
            printf ("digest: "); print_bytes(out.digest, 32);
            printf ("cipher text: "); print_bytes(out.ciphertext, out.ciphertext_size);
        }
        else{
            return ret;
        }
    }
    return ret;
}
int main(){

    int ret = 0;
    srand(time(NULL));

    if ((ret = test_sm2_gen_key()) <= 0) goto fail;
    if ((ret = test_sm2_sig_veri()) <= 0) goto fail;
    if ((ret = test_sm2_enc_dec()) <= 0) goto fail;
    if ((ret = test_der_encode_decode()) <= 0) goto fail;
    printf ("successed\n");
    return 1;

fail:
    printf ("failed, ret = %d\n", ret);
    return 0;
}