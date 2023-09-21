
#if !defined TEST_CONFIG_H
#define TEST_CONFIG_H

    //#define TEST_VECTOR_PATH "/vendor/zhangluduo/zmcrypto/vectors/"
#if defined _DEBUG && defined _WIN32
    #define TEST_VECTOR_PATH "../../vectors/"
#else
    #define TEST_VECTOR_PATH "../vectors/"
#endif
    

    #if !defined TEST_TOTAL_SEC
    #define TEST_TOTAL_SEC (3)
    #endif

#endif /* TEST_CONFIG_H */