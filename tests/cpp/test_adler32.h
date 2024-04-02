/*
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
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"

#if !defined TEST_ADLER32_H
#define TEST_ADLER32_H

void test_case_adler32(zmcrypto::sdk* _sdk);
void test_speed_adler32(zmcrypto::sdk* _sdk);
void test_info_adler32(zmcrypto::sdk* _sdk);

#endif /* TEST_ADLER32_H */