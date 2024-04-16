
#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_AES
    #include "ctr_drbg.h"
    
#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SM4
    #include "ctr_drbg.h"

#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SHA256
    #include "hash_drbg.h"

#if defined ZMCRYPTO_RANDOM_CTR_DRBG_WITH_SM3
    #include "hash_drbg.h"

#elif defined ZMCRYPTO_RANDOM_MERSENNE_TWISTER
    #include "mersenne_twister.h"

#elif defined ZMCRYPTO_RANDOM_OS
    #include <stdlib.h>

#else
    #error 'Please choose the RNG and define USED_RANDOM_CTR_DRBG, USED_RANDOM_MERSENNE_TWISTER or USED_RANDOM_OS in zmconfig.h'
#endif
