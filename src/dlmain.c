
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

#if defined __linux__
    #if !defined API
        #define API __attribute__ ((visibility("default")))
    #endif
#elif defined _WIN32
    #if !defined API
        #if defined DLL_IMPORTS
            #define API _declspec(dllimport)
        #else /* DLL_EXPORTS */
            #define API _declspec(dllexport)
        #endif
    #endif
#endif

#include "debug.h"
#include "sm4.h"

// void test(){
//     uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//     uint8_t pt [] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//     uint8_t ct [] = {0x8f, 0x78, 0x76, 0x3e, 0xe0, 0x60, 0x13, 0xe0, 0xb7, 0x62, 0x2c, 0x42, 0x8f, 0xd0, 0x52, 0x8d};

//     uint32_t klen = sizeof(key);
//     uint32_t ptlen = sizeof(pt);
//     uint32_t ctlen = sizeof(ct);

//     uint8_t* ct2 = (uint8_t*)malloc(ctlen);
//     uint8_t* pt2 = (uint8_t*)malloc(ptlen);

//     {
//         struct sm4_ctx ctx;
//         sm4_init(&ctx);
//         sm4_set_ekey(&ctx, key, klen);
//         sm4_enc_block(&ctx, pt, ct2);
//         for (int i = 0; i < 16; i++){
//             printf ("%02x ", ct2[i]);
//         }   printf ("\n");
//     }
//     {
//         struct sm4_ctx ctx;
//         sm4_init(&ctx);
//         sm4_set_dkey(&ctx, key, klen);
//         sm4_enc_block(&ctx, ct, pt2);
//         for (int i = 0; i < 16; i++){
//             printf ("%02x ", pt2[i]);
//         }   printf ("\n");
//     }
// }

#if defined __linux__
    void __attribute__ ((constructor)) load_so(void);
    void __attribute__ ((destructor)) unload_so(void);

    void load_so(void)
    {
        ZMCRYPTO_LOG("");
        zmcrypto_printf("~!@# [%d]\n", 1234);
        //test();
    }

    void unload_so(void)
    {
    }
#endif

#if defined WIN32
#include <windows.h>
    API BOOL DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
    {
       switch (dwReason)
        {
            case DLL_PROCESS_ATTACH:
                ZMCRYPTO_LOG("");
                zmcrypto_printf("~!@# [%d]\n", 1234);
                break;
            case DLL_PROCESS_DETACH:
                break;
            case DLL_THREAD_ATTACH:
                break;
            case DLL_THREAD_DETACH:
                break;
        }
        return TRUE;
    }
#endif

