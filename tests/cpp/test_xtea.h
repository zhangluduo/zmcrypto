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

#if !defined TEST_XTEA_H
#define TEST_XTEA_H

void test_case_xtea_ecb(zmcrypto::sdk* _sdk);
void test_case_xtea_cbc(zmcrypto::sdk* _sdk);
void test_case_xtea_cfb(zmcrypto::sdk* _sdk);
void test_case_xtea_ofb(zmcrypto::sdk* _sdk);
void test_case_xtea_ctr(zmcrypto::sdk* _sdk);

void test_speed_xtea(zmcrypto::sdk* _sdk);
void test_info_xtea(zmcrypto::sdk* _sdk);

#endif /* TEST_XTEA_H */