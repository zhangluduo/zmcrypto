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

#include "format_output.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#pragma warning(disable:4996)

std::string bytes_to_human_readable_format(uint64_t bytes){

#if defined __linux__
    #define base 1000
#elif defined _WIN32
    #define base 1024
#endif
    char text[50];
	memset(text, 0, 50);
    const uint64_t _kb = base;
    const uint64_t _mb = _kb * base;
    const uint64_t _gb = _mb * base;
    const uint64_t _tb = _gb * base;
    const uint64_t _eb = _tb * base;

#if defined __linux__
    if (bytes >= _eb)     { double c = bytes; sprintf (text, "%.1f EB", c /_eb); }
    else if (bytes >= _tb){ double c = bytes; sprintf (text, "%.1f TB", c /_tb); }
    else if (bytes >= _gb){ double c = bytes; sprintf (text, "%.1f GB", c /_gb); }
    else if (bytes >= _mb){ double c = bytes; sprintf (text, "%.1f MB", c /_mb); }
    else if (bytes >= _kb){ double c = bytes; sprintf (text, "%.1f KB", c /_kb); }
    else                  { sprintf (text, "%ld bytes", bytes); }
#elif defined _WIN32
    if (bytes >= _eb)     { double c = (double)bytes; sprintf (text, "%.2f EB", c /_eb); }
    else if (bytes >= _tb){ double c = (double)bytes; sprintf (text, "%.2f TB", c /_tb); }
    else if (bytes >= _gb){ double c = (double)bytes; sprintf (text, "%.2f GB", c /_gb); }
    else if (bytes >= _mb){ double c = (double)bytes; sprintf (text, "%.2f MB", c /_mb); }
    else if (bytes >= _kb){ double c = (double)bytes; sprintf (text, "%.2f KB", c /_kb); }
    else                  { sprintf (text, "%ld bytes", bytes); }
#endif

#if 0
    //537.8 MB (537,751,757 bytes)
    //63.7 kB (63,748 bytes)
    //506 bytes
    uint64_t bytes = 506;
    char text[50];
    file_bytes_to_human_readable_format(bytes, text);
    printf ("[%s]\n", text);
#endif

    return std::string(text);
}

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
        printf("The format text exceed width: '%s':%ld\n", Msg.c_str(), Msg.length());

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

