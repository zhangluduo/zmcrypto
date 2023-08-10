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

#include "format_output.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <string>

// printf("[%-*.*s]\n", 
//     5, 3, "0123456789");

void format_output(const char* const fmt, ...){
    size_t width = 120;

    char* padding = new char[width];
    memset(padding, 0, width);
    memset(padding, '.', width - 1);

    char* strp = new char[4096];
    memset(strp, 0, 4096);
    va_list args;
    va_start(args, fmt);
    const int ret = vsprintf(strp, fmt, args);
    va_end(args); 

    std::string Msg = strp;
    if (Msg.length() >= width){
        printf("The format text exceed width: '%s':%d\n", Msg.c_str(), Msg.length());

        delete[] strp;
        strp = NULL;

        delete[] padding;
        padding = NULL;
        return;
    }

    size_t pos = Msg.find('|');
    if (pos != std::string::npos){
        std::string head = Msg.substr(0, pos);
        std::string tail = Msg.substr(pos + 1);
        
        std::string strPad(padding, width - head.length() - tail.length());
        printf("%s%s%s", 
            head.c_str(), strPad.c_str(), tail.c_str()
            );
    }

    delete[] strp;
    strp = NULL;

    delete[] padding;
    padding = NULL;
}

