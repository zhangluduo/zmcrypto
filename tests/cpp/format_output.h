
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

#if !defined _FORMATOUTPUT_HEADER_H
#define _FORMATOUTPUT_HEADER_H

#include <string>
#include <stdint.h>

void format_output(const char* const fmt, ...);
std::string bytes_to_human_readable_format(uint64_t bytes);

#endif