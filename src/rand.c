
/*Define the algorithm used for RGB(Random Bit Generators) here*/
#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_AES
    #include "ctr_drbg.h"
    
#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SM4
    #include "ctr_drbg.h"

#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SHA3_256
    #include "hash_drbg.h"

#if defined ZMCRYPTO_RANDOM_HASH_DRBG_WITH_SM3
    #include "hash_drbg.h"

#else
    #error 'Please choose the RBG and define ZMCRYPTO_RANDOM_CTR_DRBG_WITH_AES, \
ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SM4, ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SM3 or \
ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SHA3_256 in zmconfig.h'
#endif

/*Define the algorithm used for RNB(Random Number Generators) here*/
#if defined ZMCRYPTO_RANDOM_MERSENNE_TWISTER
    #include "mersenne_twister.h"
#else
    #error 'Please choose the RNG and define ZMCRYPTO_RANDOM_MERSENNE_TWISTER in zmconfig.h'
#endif
