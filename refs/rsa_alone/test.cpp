#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rsa.h"
#include "sha1.h"
#include "log.h"

using namespace polarssl;

#define _VERIFY_INI_OPENSSL 1

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
    #include <openssl/evp.h>
    #include <openssl/engine.h>
#endif

const char* _n  = "8f9b262c2513eb7a1f8e726ce5f7671148faaa7fa997e072a56dbaf984197f8350c85120b1957e61acbab1add3b0e826924aeaa33d29c406a2a6dff1e675fbcd";
const char* _e  = "010001";
const char* _d  = "50482e38f3a985354abaf9e14356e239d990b90c91a5248733507afccf0aea2b8445f1b3a64e701548445c138356e57c381307b1bf61a671ec76f4a0b0229201";
const char* _p  = "f5fbf40749be9e093727dbe01c08e71ebb1257e8d879dab710c1471f9ee9db41";
const char* _q  = "95740b6bb73a6dac1836477ccf0bfc7b297047022c5167122535e6b0ade6f98d";
const char* _dp = "8757b0a60dea4693f57805dfa22d37d54dc2c301c7920c482b7cdcc046348fc1";
const char* _dq = "2f876a226570f573e7774ba0cb8fba49c8d1e62330c8ea8880c0f58e769f9ff9";
const char* _qp = "7d1515b06d3dc6a0e44d7cdd3b362facf2d812ab5ba99faf548fdcb67aec3534";

void print_bytes(char* title, unsigned char* data, int len){
    printf("%s", title);
    for (int i = 0; i < len; i++){
        printf("%02x ", data[i]);
    }
    printf("\n");
}

uint64_t get_current_timestamp_us()
{
	struct timespec tm;
	clock_gettime(CLOCK_MONOTONIC, &tm);
	double v = tm.tv_sec * 1000000.0f;
	v += tm.tv_nsec / 1000000.0f;
	return (uint64_t)v;
}

uint64_t get_current_timestamp_ns()
{
	struct timespec tm;
	clock_gettime(CLOCK_MONOTONIC, &tm);
	double v = tm.tv_sec * 1000000000.0f;
	v += tm.tv_nsec;// / 1000000.0f;
	return (uint64_t)v;
}

int _rsa_rand(void *rng_state, unsigned char *output, size_t len)
{
    for(size_t i = 0; i < len; ++i)
        output[i] = rand();
    return 0;
}

void*    _sha1_create  ()          { return new sha1_context(); }
void     _sha1_free    (void* ctx) { delete ((sha1_context*)ctx); }
uint32_t _sha1_size    ()          { return 20; }
void     _sha1_init    (void* ctx) { sha1_init((sha1_context*)ctx); }
void     _sha1_starts  (void* ctx) { sha1_starts((sha1_context*)ctx); }
void     _sha1_update  (void* ctx, unsigned char* data, uint32_t len) { sha1_update((sha1_context *)ctx, data, len ); }
void     _sha1_finish  (void* ctx, unsigned char* output) { sha1_finish((sha1_context *)ctx, output); }

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==1366950== Memcheck, a memory error detector
==1366950== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1366950== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1366950== Command: ./test
==1366950== 
check public key passed
check private key passed
RSA key(512 bits): 
 n: 8a 89 1a 02 05 0d c8 52 de 37 fb 7a 98 98 0f 4a 0c 36 84 55 f7 9f 30 cb e1 17 a2 f0 23 a2 a7 e8 03 2b c5 1f 2a 4b 8a ec b1 45 d5 b0 86 d3 89 bd d1 ab 9b 86 19 19 d0 c1 da d3 be cd fd 64 22 87 
 e: 01 00 01 
 d: 88 a0 72 4f ef a0 0a 23 00 1a 02 20 84 81 e3 02 4a 4d 31 f2 7e c6 37 1f bb 9c ce 0b 3b 79 dd 51 16 d1 a1 4d 8d b3 f4 c3 53 86 16 f2 28 87 2f 83 3e b5 2b c3 52 d4 f1 a5 26 02 58 43 56 f7 80 91 
 p: c0 9e 3f e9 66 ad 41 b0 70 4b 08 38 1f 44 7f d4 fd 46 c5 21 2f 55 d8 fa 0b 28 41 97 7c 46 79 45 
 q: b8 1f 0b d6 f0 80 ed 53 21 4b c0 37 75 3f ef 26 1c 17 09 cd 8d dd e6 ad 75 29 17 7e 6b 45 db 5b 
dp: 7c 33 ce bc 5e c3 eb 6e ad 0a 04 d3 c3 7d b4 fc 0f 11 5a 3d aa bb 2d 7d 16 42 b0 00 d1 56 d4 0d 
dq: 26 bb c9 46 d7 63 98 09 a3 f8 86 a0 64 17 26 1d 53 4d 79 6f 77 c7 d5 ce 69 d6 52 2d f3 2d 47 ff 
qp: 64 5f 39 0c c1 d7 53 08 c4 df eb 9c 09 ef 7a eb c3 d5 99 c8 4b 4b 3b 2b 18 a5 5f e3 b1 f4 3a 23 
successed
==1366950== 
==1366950== HEAP SUMMARY:
==1366950==     in use at exit: 0 bytes in 0 blocks
==1366950==   total heap usage: 2,650 allocs, 2,650 frees, 174,427 bytes allocated
==1366950== 
==1366950== All heap blocks were freed -- no leaks are possible
==1366950== 
==1366950== For lists of detected and suppressed errors, rerun with: -s
==1366950== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_gen_key(){
    int ret;
    int keybits = 512;
    int exponent = 65537;
    rsa_key key;
    rsa_init(&key);

    ret = rsa_gen_key(&key, _rsa_rand, NULL, keybits, 65537);
    if (ret != 0){
        printf("rsa_gen_key() failed\n");
        return 0;
    }

    if (rsa_check_pubkey(&key) == 0){
        printf("check public key passed\n");
    }

    if (rsa_check_privkey(&key) == 0){
        printf("check private key passed\n");
    }

    size_t  nLen = mpi_size(&(key.N ));
    size_t  eLen = mpi_size(&(key.E ));
    size_t  dLen = mpi_size(&(key.D ));
    size_t  pLen = mpi_size(&(key.P ));
    size_t  qLen = mpi_size(&(key.Q ));
    size_t dpLen = mpi_size(&(key.DP));
    size_t dqLen = mpi_size(&(key.DQ));
    size_t qpLen = mpi_size(&(key.QP));

    unsigned char*  n = new unsigned char[ nLen];
    unsigned char*  e = new unsigned char[ eLen];
    unsigned char*  d = new unsigned char[ dLen];
    unsigned char*  p = new unsigned char[ pLen];
    unsigned char*  q = new unsigned char[ qLen];
    unsigned char* dp = new unsigned char[dpLen];
    unsigned char* dq = new unsigned char[dqLen];
    unsigned char* qp = new unsigned char[qpLen];

    mpi_write_binary(&(key.N ),  n,  nLen);
    mpi_write_binary(&(key.E ),  e,  eLen);
    mpi_write_binary(&(key.D ),  d,  dLen);
    mpi_write_binary(&(key.P ),  p,  pLen);
    mpi_write_binary(&(key.Q ),  q,  qLen);
    mpi_write_binary(&(key.DP), dp, dpLen);
    mpi_write_binary(&(key.DQ), dq, dqLen);
    mpi_write_binary(&(key.QP), qp, qpLen); 
    
    printf ("RSA key(512 bits): \n");
    print_bytes(" n: ",  n,  nLen);
    print_bytes(" e: ",  e,  eLen);
    print_bytes(" d: ",  d,  dLen);
    print_bytes(" p: ",  p,  pLen);
    print_bytes(" q: ",  q,  qLen);
    print_bytes("dp: ", dp, dpLen);
    print_bytes("dq: ", dq, dqLen);
    print_bytes("qp: ", qp, qpLen);

    delete[]  n;
    delete[]  e;
    delete[]  d;
    delete[]  p;
    delete[]  q;
    delete[] dp;
    delete[] dq;
    delete[] qp;

    n = NULL;
    e = NULL;
    d = NULL;
    p = NULL;
    q = NULL;
    dp = NULL;
    dq = NULL;
    qp = NULL;

    rsa_free(&key);
    return 1;
}

int test_rsa_rand(void *rng_state, unsigned char *output, size_t len)
{
    for(size_t i = 0; i < len; ++i)
        output[i] = rand();
    return 0;
}

int test_make_rsa_pri_key(rsa_key* key)
{
    rsa_init(key);

    key->len = 512 / 8;
    mpi_init(&(key->N));
    mpi_init(&(key->E));
    mpi_init(&(key->D));
    mpi_init(&(key->P));
    mpi_init(&(key->Q));
    mpi_init(&(key->DP));
    mpi_init(&(key->DQ));
    mpi_init(&(key->QP));

    mpi_read_string(&(key->N ), 16, _n );
    mpi_read_string(&(key->E ), 16, _e );
    mpi_read_string(&(key->D ), 16, _d );
    mpi_read_string(&(key->P ), 16, _p );
    mpi_read_string(&(key->Q ), 16, _q );
    mpi_read_string(&(key->DP), 16, _dp);
    mpi_read_string(&(key->DQ), 16, _dq);
    mpi_read_string(&(key->QP), 16, _qp);

    if (rsa_check_privkey((rsa_key*)key) == 0){
        printf("check private key passed\n");
    }

    /* rsa_free(key); */
    return 1;
}

int test_make_rsa_pub_key(rsa_key* key)
{
    rsa_init(key);

    key->len = 512 / 8;
    mpi_init(&(key->N));
    mpi_init(&(key->E));
    mpi_init(&(key->D));
    mpi_init(&(key->P));
    mpi_init(&(key->Q));
    mpi_init(&(key->DP));
    mpi_init(&(key->DQ));
    mpi_init(&(key->QP));

    mpi_read_string(&(key->N ), 16, _n );
    mpi_read_string(&(key->E ), 16, _e );

    if (rsa_check_pubkey((rsa_key*)key) == 0){
        printf("check public key passed\n");
    }

    /* rsa_free(key); */
    return 1;
}

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1

RSA* make_openssl_rsa_pub_key(){

    /* They doesn't need to be released. 
    When 'r' is released, it is released along with it */
    BIGNUM* bnRsaN  = BN_new();
    BIGNUM* bnRsaE  = BN_new();

    BN_hex2bn(&bnRsaN , _n );
    BN_hex2bn(&bnRsaE , _e );

    RSA* r = RSA_new();
    RSA_set0_key(r, bnRsaN, bnRsaE, NULL);
    return r;
}

RSA* make_openssl_rsa_pri_key(){

    /* They doesn't need to be released. 
    When 'r' is released, it is released along with it */
    BIGNUM* bnRsaN  = BN_new();
    BIGNUM* bnRsaE  = BN_new();
    BIGNUM* bnRsaD  = BN_new();
    BIGNUM* bnRsaP  = BN_new();
    BIGNUM* bnRsaQ  = BN_new();
    BIGNUM* bnRsaDP = BN_new();
    BIGNUM* bnRsaDQ = BN_new();
    BIGNUM* bnRsaQP = BN_new();

    BN_hex2bn(&bnRsaN , _n );
    BN_hex2bn(&bnRsaE , _e );
    BN_hex2bn(&bnRsaD , _d );
    BN_hex2bn(&bnRsaP , _p );
    BN_hex2bn(&bnRsaQ , _q );
    BN_hex2bn(&bnRsaDP, _dp);
    BN_hex2bn(&bnRsaDQ, _dq);
    BN_hex2bn(&bnRsaQP, _qp);

    RSA* r = RSA_new();
    {
        RSA_set0_key       (r, bnRsaN, bnRsaE, bnRsaD);
        RSA_set0_factors   (r, bnRsaP, bnRsaQ);
        RSA_set0_crt_params(r, bnRsaDP, bnRsaDQ, bnRsaQP);
    }

    return r;
}

int test_evp_rsa_sig_veri(unsigned char* sig, size_t siglen)
{
    LOG("");

    {
        RSA* rsa = make_openssl_rsa_pub_key();

        EVP_MD_CTX* mdctx =  EVP_MD_CTX_create();
        EVP_MD* md = (EVP_MD*)(EVP_MD*)EVP_get_digestbyname("sha1");//EVP_sha1();
        EVP_PKEY* pkey =  EVP_PKEY_new();
        EVP_PKEY_CTX* pkeyctx = NULL;

        if (EVP_PKEY_set1_RSA(pkey, rsa) != 1)
        {
            printf("EVP_PKEY_set1_RSA is failed.\n");
            goto fail2;
        }

        if (EVP_DigestVerifyInit(mdctx, &pkeyctx, md, NULL, pkey) <= 0) {
            LOG("EVP_DigestSignInit failed");
            goto fail2;
        }

        /*RSA_PKCS1_PADDING RSA_PKCS1_PSS_PADDING*/
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyctx, RSA_PKCS1_PADDING) <= 0) {
            LOG("EVP_PKEY_CTX_set_rsa_padding failed");
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

        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(mdctx);
        RSA_free(rsa);
        return 1;

fail2:
        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(mdctx);
        RSA_free(rsa);
        return 0;
    }

    return 1;
}

int test_evp_rsa_sig_veri2(unsigned char* sig, size_t siglen)
{
    LOG("");

    {
        RSA* rsa = make_openssl_rsa_pub_key();

        EVP_MD_CTX* mdctx =  EVP_MD_CTX_create();
        EVP_MD* md = (EVP_MD*)(EVP_MD*)EVP_get_digestbyname("sha1");//EVP_sha1();
        EVP_PKEY* pkey =  EVP_PKEY_new();
        EVP_PKEY_CTX* pkeyctx = NULL;

        if (EVP_PKEY_set1_RSA(pkey, rsa) != 1)
        {
            printf("EVP_PKEY_set1_RSA is failed.\n");
            goto fail2;
        }

        if (EVP_DigestVerifyInit(mdctx, &pkeyctx, md, NULL, pkey) <= 0) {
            LOG("EVP_DigestSignInit failed");
            goto fail2;
        }

        // ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING); LOG("ret: %d", ret);
        // ret = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha1()); LOG("ret: %d", ret);
        // ret = EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha1());LOG("ret: %d", ret);
        // ret = EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label, 5); LOG("ret: %d", ret);

        /*RSA_PKCS1_PADDING RSA_PKCS1_PSS_PADDING*/
        if (EVP_PKEY_CTX_set_rsa_padding(pkeyctx, RSA_PKCS1_PSS_PADDING) <= 0) {
            LOG("EVP_PKEY_CTX_set_rsa_padding failed");
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

        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(mdctx);
        RSA_free(rsa);
        return 1;

fail2:
        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_destroy(mdctx);
        RSA_free(rsa);
        return 0;
    }

    return 1;
}
#endif

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==1626391== Memcheck, a memory error detector
==1626391== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1626391== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1626391== Command: ./test
==1626391== 
check private key passed
sig: 5e 03 68 ca 79 c8 ac 16 bd 7c 9f b2 e5 91 e4 8f fe 13 af 91 a9 d8 c1 f4 41 cd b8 56 d2 87 31 a1 be 25 e9 0b ee 5f ee e2 82 de 11 02 78 9c 94 ef 0c 0e bd 54 e7 eb bc c2 ec 2a 2e f4 c6 72 ec fd 
[BEANPOD][2022-10-29T17:57:37+0800][1626391] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_sig_veri(unsigned char*, size_t):273 
[BEANPOD][2022-10-29T17:57:37+0800][1626391] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_sig_veri(unsigned char*, size_t):309 verify successed
[BEANPOD][2022-10-29T17:57:37+0800][1626391] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_rsassa_pkcs1_v15(polarssl::rsa_key*):387 verify in OpenSSL successed
verify successed
successed
==1626391== 
==1626391== HEAP SUMMARY:
==1626391==     in use at exit: 0 bytes in 0 blocks
==1626391==   total heap usage: 1,322 allocs, 1,322 frees, 141,802 bytes allocated
==1626391== 
==1626391== All heap blocks were freed -- no leaks are possible
==1626391== 
==1626391== For lists of detected and suppressed errors, rerun with: -s
==1626391== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_rsassa_pkcs1_v15(rsa_key* key){

    unsigned char* sig = NULL;
    int siglen = 0;

    /* signagure */
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        rsa_rsassa_pkcs1_v15_sign_start(&digest_ctx);
        rsa_rsassa_pkcs1_v15_sign_update(&digest_ctx, (const unsigned char*)"helloworld", 10);

        siglen = rsa_helper_rsassa_pkcs1_v15_fixed_len(key->len);
        
        sig = new unsigned char[siglen];
        {
            if (rsa_rsassa_pkcs1_v15_sign_finish(key, &digest_ctx, _rsa_rand, NULL, sig) < 0){
                goto fail;
            }
            print_bytes("sig: ", sig, siglen);
        }

        #if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
            if (test_evp_rsa_sig_veri(sig, siglen) <= 0){
                LOG("verify in OpenSSL failed");
            }else{
                LOG("verify in OpenSSL successed");
            }
        #endif

        rsa_digest_free(&digest_ctx);
        goto veri;

    fail:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }

veri:
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        rsa_rsassa_pkcs1_v15_verify_start(&digest_ctx);
        rsa_rsassa_pkcs1_v15_verify_update(&digest_ctx, (const unsigned char*)"helloworld", 10);

        {
            if (rsa_rsassa_pkcs1_v15_verify_finish(key, &digest_ctx, _rsa_rand, NULL, sig) < 0){
                printf("verify failed\n");
                goto fail2;
            }
            printf("verify successed\n");
        }

        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 1;

    fail2:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }
    return 1;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==1627976== Memcheck, a memory error detector
==1627976== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1627976== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1627976== Command: ./test
==1627976== 
check private key passed
sig: 5e 03 68 ca 79 c8 ac 16 bd 7c 9f b2 e5 91 e4 8f fe 13 af 91 a9 d8 c1 f4 41 cd b8 56 d2 87 31 a1 be 25 e9 0b ee 5f ee e2 82 de 11 02 78 9c 94 ef 0c 0e bd 54 e7 eb bc c2 ec 2a 2e f4 c6 72 ec fd 
[BEANPOD][2022-10-29T18:04:16+0800][1627976] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_sig_veri(unsigned char*, size_t):273 
[BEANPOD][2022-10-29T18:04:16+0800][1627976] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_sig_veri(unsigned char*, size_t):309 verify successed
[BEANPOD][2022-10-29T18:04:16+0800][1627976] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_rsassa_pkcs1_v15_2(polarssl::rsa_key*):470 verify in OpenSSL successed
verify successed
successed
==1627976== 
==1627976== HEAP SUMMARY:
==1627976==     in use at exit: 0 bytes in 0 blocks
==1627976==   total heap usage: 1,293 allocs, 1,293 frees, 139,962 bytes allocated
==1627976== 
==1627976== All heap blocks were freed -- no leaks are possible
==1627976== 
==1627976== For lists of detected and suppressed errors, rerun with: -s
==1627976== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_rsassa_pkcs1_v15_2(rsa_key* key){
    int siglen = 0;
    unsigned char* sig = NULL;
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        siglen = rsa_helper_rsassa_pkcs1_v15_fixed_len(key->len);
        sig = new unsigned char[siglen];
        {
            unsigned char helloworld_sha1[20] = { 0x6a, 0xdf, 0xb1, 0x83, 0xa4, 0xa2, 0xc9, 0x4a, 0x2f, 0x92, 0xda, 0xb5, 0xad, 0xe7, 0x62, 0xa4, 0x78, 0x89, 0xa5, 0xa1 };
            if (rsa_rsassa_pkcs1_v15_sign_oneshot(key, &digest_ctx, _rsa_rand, NULL, helloworld_sha1, sig) < 0){
                goto fail;
            }
            print_bytes("sig: ", sig, siglen);
        }

    #if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
        if (test_evp_rsa_sig_veri(sig, siglen) <= 0){
            LOG("verify in OpenSSL failed");
        }else{
            LOG("verify in OpenSSL successed");
        }
    #endif

        /*delete[] sig;*/
        /*sig = NULL;*/
        rsa_digest_free(&digest_ctx);
        /*return 1;*/
        goto veri;

    fail:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }

    veri:
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        {
            unsigned char helloworld_sha1[20] = { 0x6a, 0xdf, 0xb1, 0x83, 0xa4, 0xa2, 0xc9, 0x4a, 0x2f, 0x92, 0xda, 0xb5, 0xad, 0xe7, 0x62, 0xa4, 0x78, 0x89, 0xa5, 0xa1 };
            /* sig[0] = 0x00; test for make bad signature*/
            if (rsa_rsassa_pkcs1_v15_verify_oneshot(key, &digest_ctx, _rsa_rand, NULL, helloworld_sha1, sig) < 0){
                printf ("verify failed\n");
                goto fail2;
            }
            printf ("verify successed\n");
        }

        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 1;

    fail2:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }
}

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
int test_evp_rsa_enc_dec(unsigned char* ct, int ctlen){
    int ret;
    unsigned char pt[1024];
    size_t ptlen = 1024;

    {
        RSA* rsa = make_openssl_rsa_pri_key();

        EVP_PKEY* pkey =  NULL;
        EVP_PKEY_CTX* pctx = NULL;

        /* EVP_PKEY and EVP_PKEY_CTX */
        pkey = EVP_PKEY_new();
        if (!pkey){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_set1_RSA(pkey, rsa); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }
        ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_RSA); 
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

        printf ("openssl output pt: ");
        for (size_t i = 0; i < ptlen; i++){
            printf ("%02x ", pt[i]);
        }   printf ("\n");

        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (rsa) { RSA_free(rsa); }
        LOG("successed");
        return 1;

fail2:
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (rsa) { RSA_free(rsa); }
        LOG("failed");
        return 1;
    }

    return 0;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==2250903== Memcheck, a memory error detector
==2250903== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==2250903== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==2250903== Command: ./test
==2250903== 
check private key passed
construct db: 64 c6 53 74 db ab 6f e3 76 27 48 19 6d 9d 3a 96 10 e2 e5 a9 00 00 00 00 00 00 00 00 00 00 00 00 01 68 65 6c 6c 6f 77 6f 72 6c 64 
maskedDB: 0d 9f 2a af d4 c3 2f 72 1c b4 77 0b bf a4 9e 3a bc 63 60 62 e4 38 33 fc 99 31 3d 14 87 c5 ae 8e 7e ff 66 bb 29 80 02 b7 1d 63 3c 
maskedSeed: 5e e7 90 52 da 86 ed 1e ce 43 bf e8 90 7c 86 f9 94 10 0f 0b 
ct: 52 4d 93 09 2a f5 7c a3 2f 09 a1 12 36 2d f5 63 0a 65 d8 67 c0 55 e7 ad f7 9a 5b fd 3f e4 bd 75 b2 0f 30 c2 5f 68 3a c8 02 c0 2a d3 04 e4 0a 61 e7 b9 ec 04 19 02 7f 7b d5 d7 8c 59 8a a8 c2 a2 
[BEANPOD][2022-11-05T17:28:03+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):641 ret: 1
[BEANPOD][2022-11-05T17:28:03+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):642 ret: 1
[BEANPOD][2022-11-05T17:28:03+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):643 ret: 1
[BEANPOD][2022-11-05T17:28:03+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):644 ret: 1
openssl output pt: 68 65 6c 6c 6f 77 6f 72 6c 64 
[BEANPOD][2022-11-05T17:28:04+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):668 successed
[BEANPOD][2022-11-05T17:28:04+0800][2250903] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_rsaes_oaep(polarssl::rsa_key*):768 decrypt in OpenSSL successed
successed
==2250903== 
==2250903== HEAP SUMMARY:
==2250903==     in use at exit: 0 bytes in 0 blocks
==2250903==   total heap usage: 3,213 allocs, 3,213 frees, 204,407 bytes allocated
==2250903== 
==2250903== All heap blocks were freed -- no leaks are possible
==2250903== 
==2250903== For lists of detected and suppressed errors, rerun with: -s
==2250903== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_evp_rsa_oaep_enc_dec(unsigned char* ct, int ctlen){
    int ret;
    unsigned char pt[1024];
    size_t ptlen = 1024;

    {
        RSA* rsa = make_openssl_rsa_pri_key();
        char* label = (char*)malloc(20); /* DO NOT RELEASE IT */
        strcpy(label, "label");

        EVP_PKEY* pkey =  NULL;
        EVP_PKEY_CTX* pctx = NULL;
        EVP_MD* md = (EVP_MD*)(EVP_MD*)EVP_get_digestbyname("sha1");//EVP_sha1();

        /* EVP_PKEY and EVP_PKEY_CTX */
        pkey = EVP_PKEY_new();
        if (!pkey){
            LOG("failed");
            goto fail2;
        }

        ret = EVP_PKEY_set1_RSA(pkey, rsa); 
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }
        ret = EVP_PKEY_set_alias_type(pkey, EVP_PKEY_RSA); 
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

        /*
        ret = EVP_PKEY_CTX_ctrl_str(pctx,"rsa_padding_mode","oaep");LOG("ret: %d", ret);
        ret = EVP_PKEY_CTX_ctrl_str(pctx,"rsa_oaep_md","sha1");LOG("ret: %d", ret);
        ret = EVP_PKEY_CTX_ctrl_str(pctx,"rsa_mgf1_md","sha1");LOG("ret: %d", ret);
        */
       
        ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING); LOG("ret: %d", ret);
        ret = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha1()); LOG("ret: %d", ret);
        ret = EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha1());LOG("ret: %d", ret);
        ret = EVP_PKEY_CTX_set0_rsa_oaep_label(pctx, label, 5); LOG("ret: %d", ret);

        ret = EVP_PKEY_decrypt(pctx, pt, &ptlen, (const unsigned char*)ct, ctlen);
        if (ret <= 0){
            LOG("failed");
            goto fail2;
        }

        printf ("openssl output pt: ");
        for (size_t i = 0; i < ptlen; i++){
            printf ("%02x ", pt[i]);
        }   printf ("\n");

        /*
        what fuck OpenSSL!
        if we are 'free(label);', then 'EVP_PKEY_CTX_free(pctx);' crash! 
        and very interesting, no memory leaks occur here.
        Zhang Luduo, 2022-11-05
        */

        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (rsa) { RSA_free(rsa); }
        LOG("successed");
        return 1;

fail2:
        /*EVP_MD_meth_free(md); DO NOT RELEASE IT */
        if (pkey) { EVP_PKEY_free(pkey); }
        if (pctx) { EVP_PKEY_CTX_free(pctx); }
        if (rsa) { RSA_free(rsa); }
        LOG("failed");
        return 0;
    }

    return 0;
}
#endif

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==1453379== Memcheck, a memory error detector
==1453379== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==1453379== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==1453379== Command: ./test
==1453379== 
check public key passed
check private key passed
openssl output pt: 68 65 6c 6c 6f 77 6f 72 6c 64 
[BEANPOD][2022-10-27T17:42:42+0800][1453379] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_enc_dec(unsigned char*, int):460 successed
[BEANPOD][2022-10-27T17:42:42+0800][1453379] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_rsaes_pkcs1_v15(polarssl::rsa_key*):485 decrypt in OpenSSL successed
ct: 07 fd 8a 18 ad ae f3 94 b7 a3 94 e9 ca 9e 90 f8 20 9a c7 15 15 0a 33 8a 6f db 25 ed b7 34 01 dd e6 63 5c cf 24 cc 08 1d 4b 55 cc 1b 84 cb a5 5f 05 3e de 41 20 44 f0 bb 2c 9d f5 2e f5 97 16 01 
pt: 68 65 6c 6c 6f 77 6f 72 6c 64 
successed
==1453379== 
==1453379== HEAP SUMMARY:
==1453379==     in use at exit: 0 bytes in 0 blocks
==1453379==   total heap usage: 3,696 allocs, 3,696 frees, 235,640 bytes allocated
==1453379== 
==1453379== All heap blocks were freed -- no leaks are possible
==1453379== 
==1453379== For lists of detected and suppressed errors, rerun with: -s
==1453379== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_rsaes_pkcs1_v15(rsa_key* key)
{
    const char* msg = "helloworld";
    unsigned char ct[64];
    rsa_rsaes_pkcs1_v15_encrypt(key, _rsa_rand, NULL, strlen(msg), (const unsigned char*)msg, ct);

#if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
    if (test_evp_rsa_enc_dec(ct, 64) <= 0){
        LOG("decrypt in OpenSSL failed");
    }else{
        LOG("decrypt in OpenSSL successed");
    }
#endif

    unsigned char pt[64];
    size_t olen = 64;
    rsa_rsaes_pkcs1_v15_decrypt(key, _rsa_rand, NULL, ct, pt, &olen);

    print_bytes("ct: ", ct, 64);
    print_bytes("pt: ", pt, olen);

    return 1;
}

/*
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ valgrind ./test 
==2411107== Memcheck, a memory error detector
==2411107== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==2411107== Using Valgrind-3.18.1 and LibVEX; rerun with -h for copyright info
==2411107== Command: ./test
==2411107== 
check private key passed
==2411107== Use of uninitialised value of size 8
==2411107==    at 0x4DB266A: _itoa_word (_itoa.c:180)
==2411107==    by 0x4DCE5A4: __vfprintf_internal (vfprintf-internal.c:1687)
==2411107==    by 0x4E8508A: __printf_chk (printf_chk.c:33)
==2411107==    by 0x10DD86: rsa_rsaes_oaep_encrypt (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x119EA2: test_rsaes_oaep(polarssl::rsa_key*) (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x10B7B4: main (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107== 
==2411107== Conditional jump or move depends on uninitialised value(s)
==2411107==    at 0x4DB267C: _itoa_word (_itoa.c:180)
==2411107==    by 0x4DCE5A4: __vfprintf_internal (vfprintf-internal.c:1687)
==2411107==    by 0x4E8508A: __printf_chk (printf_chk.c:33)
==2411107==    by 0x10DD86: rsa_rsaes_oaep_encrypt (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x119EA2: test_rsaes_oaep(polarssl::rsa_key*) (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x10B7B4: main (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107== 
==2411107== Conditional jump or move depends on uninitialised value(s)
==2411107==    at 0x4DCF258: __vfprintf_internal (vfprintf-internal.c:1687)
==2411107==    by 0x4E8508A: __printf_chk (printf_chk.c:33)
==2411107==    by 0x10DD86: rsa_rsaes_oaep_encrypt (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x119EA2: test_rsaes_oaep(polarssl::rsa_key*) (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x10B7B4: main (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107== 
==2411107== Conditional jump or move depends on uninitialised value(s)
==2411107==    at 0x4DCE71E: __vfprintf_internal (vfprintf-internal.c:1687)
==2411107==    by 0x4E8508A: __printf_chk (printf_chk.c:33)
==2411107==    by 0x10DD86: rsa_rsaes_oaep_encrypt (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x119EA2: test_rsaes_oaep(polarssl::rsa_key*) (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107==    by 0x10B7B4: main (in /home/zhangluduo/Documents/rsa_alone/test)
==2411107== 
output: 00 aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa 00 00 00 90 21 00 00 e8 03 00 00 05 00 00 00 00 00 00 00 05 88 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 
construct db: 64 c6 53 74 db ab 6f e3 76 27 48 19 6d 9d 3a 96 10 e2 e5 a9 00 00 00 00 00 00 00 00 00 00 00 00 01 68 65 6c 6c 6f 77 6f 72 6c 64 
output: 00 aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa 64 c6 53 74 db ab 6f e3 76 27 48 19 6d 9d 3a 96 10 e2 e5 a9 00 00 00 00 00 00 00 00 00 00 00 00 01 68 65 6c 6c 6f 77 6f 72 6c 64 
maskedDB: 91 1f e5 e7 0e 97 b3 b6 34 07 a7 3a 70 f5 90 4c 7d 74 78 df 32 3a 50 c5 39 a3 b4 ff dc 7b 90 e0 3b e1 69 e4 34 ba d6 e6 c6 28 b0 
output: 00 aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa 91 1f e5 e7 0e 97 b3 b6 34 07 a7 3a 70 f5 90 4c 7d 74 78 df 32 3a 50 c5 39 a3 b4 ff dc 7b 90 e0 3b e1 69 e4 34 ba d6 e6 c6 28 b0 
maskedSeed: 32 ba 29 bc 6e f9 64 4d 3c d0 40 3d 24 96 f6 05 58 01 51 fd 
output: 00 32 ba 29 bc 6e f9 64 4d 3c d0 40 3d 24 96 f6 05 58 01 51 fd 91 1f e5 e7 0e 97 b3 b6 34 07 a7 3a 70 f5 90 4c 7d 74 78 df 32 3a 50 c5 39 a3 b4 ff dc 7b 90 e0 3b e1 69 e4 34 ba d6 e6 c6 28 b0 
ct: 25 e6 62 76 e9 97 aa 2e 43 db a2 e1 77 07 8c 5d b6 38 33 ec fb ba 5f 20 7a 86 ed da d3 56 4a 07 56 4e 5e 04 de 4a 7a e4 12 3c 6c e7 9a ad 5e 10 dc 93 e5 37 63 8d 40 36 8f 91 ed 1f 33 6b 33 32 
[BEANPOD][2022-11-07T15:07:28+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):689 ret: 1
[BEANPOD][2022-11-07T15:07:28+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):690 ret: 1
[BEANPOD][2022-11-07T15:07:28+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):691 ret: 1
[BEANPOD][2022-11-07T15:07:28+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):692 ret: 1
openssl output pt: 68 65 6c 6c 6f 77 6f 72 6c 64 
[BEANPOD][2022-11-07T15:07:29+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_evp_rsa_oaep_enc_dec(unsigned char*, int):716 successed
[BEANPOD][2022-11-07T15:07:29+0800][2411107] /home/zhangluduo/Documents/rsa_alone/test.cpp, int test_rsaes_oaep(polarssl::rsa_key*):799 decrypt in OpenSSL successed
rsa_private output: 00 32 ba 29 bc 6e f9 64 4d 3c d0 40 3d 24 96 f6 05 58 01 51 fd 91 1f e5 e7 0e 97 b3 b6 34 07 a7 3a 70 f5 90 4c 7d 74 78 df 32 3a 50 c5 39 a3 b4 ff dc 7b 90 e0 3b e1 69 e4 34 ba d6 e6 c6 28 b0 
pt: 68 65 6c 6c 6f 77 6f 72 6c 64 
successed
==2411107== 
==2411107== HEAP SUMMARY:
==2411107==     in use at exit: 0 bytes in 0 blocks
==2411107==   total heap usage: 3,905 allocs, 3,905 frees, 245,607 bytes allocated
==2411107== 
==2411107== All heap blocks were freed -- no leaks are possible
==2411107== 
==2411107== Use --track-origins=yes to see where uninitialised values come from
==2411107== For lists of detected and suppressed errors, rerun with: -s
==2411107== ERROR SUMMARY: 180 errors from 4 contexts (suppressed: 0 from 0)
zhangluduo@zhangluduo-B85-HD3:~/Documents/rsa_alone$ 
*/
int test_rsaes_oaep(rsa_key* key){

    rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1};

    unsigned char ct[200];
    unsigned char pt[200];
    size_t olen = 200;
    if (rsa_rsaes_oaep_encrypt(key, _rsa_rand, NULL, &digest_fn, (const unsigned char*)"label", 5, (const unsigned char*)"helloworld", 10, ct) != 0){
        goto fail;
    }

    print_bytes("ct: ", ct, 64);

    #if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
        if (test_evp_rsa_oaep_enc_dec(ct, 64) <= 0){
            LOG("decrypt in OpenSSL failed");
        }else{
            LOG("decrypt in OpenSSL successed");
        }
    #endif

    if (rsa_rsaes_oaep_decrypt(key,  _rsa_rand, NULL, &digest_fn, (const unsigned char*)"label", 5, ct, pt, &olen) != 0)
    {
        goto fail;
    }

    print_bytes("pt: ", pt, olen);

    return 1;
fail:
    return 0;
}

int test_rsassa_pss(rsa_key* key){

    unsigned char* sig = NULL;
    int siglen = 0;

    /* signagure */
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        rsa_rsassa_pss_sign_start(&digest_ctx);
        rsa_rsassa_pss_sign_update(&digest_ctx, (const unsigned char*)"helloworld", 10);

        siglen = rsa_helper_rsassa_pss_fixed_len(key->len);
        
        sig = new unsigned char[siglen];
        {
            if (rsa_rsassa_pss_sign_finish(key, &digest_ctx, _rsa_rand, NULL, sig) < 0){
                goto fail;
            }
            print_bytes("sig: ", sig, siglen);
        }

        #if defined _VERIFY_INI_OPENSSL && _VERIFY_INI_OPENSSL == 1
            /*sig[0] = 0x00; make bad signagure */
            if (test_evp_rsa_sig_veri2(sig, siglen) <= 0){
                LOG("verify in OpenSSL failed");
            }else{
                LOG("verify in OpenSSL successed");
            }
        #endif

        rsa_digest_free(&digest_ctx);
        goto veri;

    fail:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }

veri:
    {
        rsa_digest_context digest_ctx;
        rsa_digest_fn digest_fn = { _sha1_create, _sha1_free, _sha1_size, _sha1_init, _sha1_starts, _sha1_update, _sha1_finish, E_RSA_DIGEST_SHA1 };
        rsa_digest_create(&digest_ctx, &digest_fn);

        rsa_rsassa_pss_verify_start(&digest_ctx);
        rsa_rsassa_pss_verify_update(&digest_ctx, (const unsigned char*)"helloworld", 10);

        {
            /*sig[0] = 0x00; make bad signagure */
            if (rsa_rsassa_pss_verify_finish(key, &digest_ctx, _rsa_rand, NULL, sig) < 0){
                printf("verify failed\n");
                goto fail2;
            }
            printf("verify successed\n");
        }

        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 1;

    fail2:
        delete[] sig;
        sig = NULL;
        rsa_digest_free(&digest_ctx);
        return 0;
    }
    return 1;
}

int main(){

    int ret;
    srand(time(NULL));

    if (test() <= 0) goto fail;
    if (test_gen_key() <= 0) goto fail;

    {
    rsa_key key;
    if (test_make_rsa_pub_key(&key)  <= 0) goto fail;
    rsa_free(&key);
    }

    {
    rsa_key key;
    if (test_make_rsa_pri_key(&key)  <= 0) goto fail;
    if (test_rsaes_pkcs1_v15(&key) <= 0) goto fail;
    rsa_free(&key);
    }

    {
    rsa_key key;
    if (test_make_rsa_pri_key(&key)  <= 0) goto fail;
    if (test_rsassa_pkcs1_v15(&key) <= 0) goto fail;
    rsa_free(&key);
    }

    {
    rsa_key key;
    if (test_make_rsa_pri_key(&key)  <= 0) goto fail;
    if (test_rsassa_pkcs1_v15_2(&key) <= 0) goto fail;
    rsa_free(&key);
    }

    {
    rsa_key key;
    if (test_make_rsa_pri_key(&key)  <= 0) goto fail;
    if (test_rsaes_oaep(&key) <= 0) goto fail;
    rsa_free(&key);
    }

    {
    rsa_key key;
    if (test_make_rsa_pri_key(&key)  <= 0) goto fail;
    if (test_rsassa_pss(&key) <= 0) goto fail;
    rsa_free(&key);
    }

    printf ("successed\n");
    return 1;
fail:
    printf ("failed\n");
    return 0;
}
