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

#if !defined TEST_GCM_H
#define TEST_GCM_H

void test_case_gcm(zmcrypto::sdk* _sdk);
void test_speed_gcm(zmcrypto::sdk* _sdk);
void test_info_gcm(zmcrypto::sdk* _sdk);

#endif /* TEST_GCM_H */