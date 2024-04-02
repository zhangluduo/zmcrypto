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

#if !defined TEST_BLOWFISH_H
#define TEST_BLOWFISH_H

void test_case_blowfish_ecb(zmcrypto::sdk* _sdk);
void test_case_blowfish_cbc(zmcrypto::sdk* _sdk);
void test_case_blowfish_cfb(zmcrypto::sdk* _sdk);
void test_case_blowfish_ofb(zmcrypto::sdk* _sdk);
void test_case_blowfish_ctr(zmcrypto::sdk* _sdk);

void test_speed_blowfish(zmcrypto::sdk* _sdk);
void test_info_blowfish(zmcrypto::sdk* _sdk);

#endif /* TEST_BLOWFISH_H_H */