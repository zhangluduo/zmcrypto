
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

#if !defined ZMCRYPTO_DLMAIN_H
#define ZMCRYPTO_DLMAIN_H

#include "zmconfig.h"

#ifdef  __cplusplus
extern "C" {
#endif

    #if defined __linux__
        void load_dl(void);
        void unload_dl(void);
    #endif

    #if defined WIN32
        #include <windows.h>
        BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD dwReason, LPVOID lpvReserved);
    #endif
    
#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_DLMAIN_H */

