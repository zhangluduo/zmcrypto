
#if defined USED_RANDOM_CTR_DRBG
    #include "drbg.h"
    
#elif defined USED_RANDOM_MERSENNE_TWISTER
    #include "mersenne.h"

#elif defined USED_RANDOM_OS
    #include <stdlib.h>

#else
    #error 'Please choose the RNG and define USED_RANDOM_CTR_DRBG, USED_RANDOM_MERSENNE_TWISTER or USED_RANDOM_OS in zmconfig.h'
#endif
