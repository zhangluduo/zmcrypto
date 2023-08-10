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

#if !defined VECTOR_FILE_H
#define VECTOR_FILE_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include <string>
#include <vector>

typedef struct _key_val_pair
{
    std::string label;
    std::string data;
} key_val_pair;

typedef std::vector<key_val_pair> key_val_vec;

bool read_vector_data(const char* filename, std::vector<key_val_vec>& test_vec);
bool get_key_val_pair(std::vector<key_val_vec>& test_vec, size_t index, std::string key, std::string& val);

#endif /* VECTOR_FILE_H */