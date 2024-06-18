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

#if !defined HOOK_H
#define HOOK_H

#include "../src/zmcrypto.h"

#ifdef  __cplusplus
extern "C" {
#endif

    API zmerror hook_start(void* modue);
	API zmerror hook_finish();

#ifdef  __cplusplus
}
#endif

#endif /* ZMCRYPTO_AES_H */
