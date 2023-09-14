
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

#if defined __linux__
    void __attribute__ ((constructor)) load_so(void);
    void __attribute__ ((destructor)) unload_so(void);

    void load_so(void)
    {
    }

    void unload_so(void)
    {
    }
#endif

#if defined WIN32
    #include <windows.h>
    BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
    {
        switch (dwReason)
        {
            case DLL_PROCESS_ATTACH:
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

