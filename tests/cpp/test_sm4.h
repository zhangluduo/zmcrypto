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
 *   Date: Feb. 2024
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"

#if !defined TEST_SM4_H
#define TEST_SM4_H

void test_case_sm4_ecb(zmcrypto::sdk* _sdk);
void test_case_sm4_cbc(zmcrypto::sdk* _sdk);
void test_case_sm4_cfb(zmcrypto::sdk* _sdk);
void test_case_sm4_ofb(zmcrypto::sdk* _sdk);
void test_case_sm4_ctr(zmcrypto::sdk* _sdk);

void test_speed_sm4(zmcrypto::sdk* _sdk);
void test_info_sm4(zmcrypto::sdk* _sdk);

#endif /* TEST_SM4_H */