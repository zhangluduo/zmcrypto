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
 *   Date: Nov 2022
 *   Home: https://zmcrypto.cn/
 *         https://github.com/zhangluduo/
 */

#include "zmcryptosdk.h"

#if !defined TEST_AES_H
#define TEST_AES_H

void test_case_aes(zmcrypto::sdk* _sdk);
void test_case_aes_ecb(zmcrypto::sdk* _sdk);
void test_case_aes_cbc(zmcrypto::sdk* _sdk);
void test_case_aes_cfb(zmcrypto::sdk* _sdk);
void test_case_aes_ofb(zmcrypto::sdk* _sdk);
void test_case_aes_ctr(zmcrypto::sdk* _sdk);

void test_speed_aes(zmcrypto::sdk* _sdk);
void test_info_aes(zmcrypto::sdk* _sdk);

#endif /* TEST_AES_H */