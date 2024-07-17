
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
 *   Date: Nov. 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/zmcrypto/
 */


#if defined __linux__
    void __attribute__ ((constructor)) load_dl(void);
    void __attribute__ ((destructor)) unload_dl(void);

    void load_dl(void) { }
    void unload_dl(void) { }
#endif

#if defined WIN32
#include <windows.h>
    BOOL __stdcall DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
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

