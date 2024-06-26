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
 *   Date: Sep. 2023
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"

#if !defined TEST_RC4_H
#define TEST_RC4_H

void test_case_rc4(zmcrypto::sdk* _sdk);
void test_speed_rc4(zmcrypto::sdk* _sdk);
void test_info_rc4(zmcrypto::sdk* _sdk);

#endif /* TEST_RC4_H */