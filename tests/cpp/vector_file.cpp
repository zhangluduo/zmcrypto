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

#include "warning_disable.h"
#include "vector_file.h"
#include <memory.h>

#define _LINE_MAX_CHAR (4096)

bool _hex_char_to_byte(uint8_t* d, char c)
{
    *d = 0xff;
    if (c >= 0x30 && c <= 0x39) {*d = c - 0x30; return true; }
    if (c >= 0x41 && c <= 0x46) {*d = c - 0x37; return true; }
    if (c >= 0x61 && c <= 0x66) {*d = c - 0x57; return true; }
    return false;
}

bool _hexstring_to_binary(char* hex, uint8_t** output, uint32_t* output_len)
{
    uint32_t slen = (uint32_t)strlen(hex);
    if (slen == 0){
        return false;
    }
    int buffer_len = slen % 2 == 0 ? slen / 2 : slen / 2 + 1;
    uint8_t* buffer = new uint8_t[buffer_len];
    memset(buffer, 0, buffer_len);

    int nbytes = 0;
    for (uint32_t i = 0, j = 0; i < slen; i++, j++)
    {
        char ch = hex[i];

        if (ch == 0x20 || ch == '\r' || ch == '\n')
        {
            j--;
            continue;
        }

        uint8_t d = 0;
        if (!_hex_char_to_byte(&d, ch))
        {
            delete[] (buffer);
            buffer = NULL;
            return 0;
        }

        nbytes++;
        buffer[j / 2] = buffer[j / 2] | (j % 2 == 0 ? d << 4 : d);
    }

    if (output){
        *output = buffer;
    }
    if (output_len){
        *output_len = nbytes % 2 == 0 ? nbytes / 2 : nbytes / 2 + 1;
    }

    return true;
}

void _hexstring_to_binary_free(uint8_t** output){
    if (output && *output){
        delete[] (*output);
        *output = NULL;
    }
}

/* parse from 'label:data' format */
bool parse_label_data(std::string s, std::string& label, std::string& data){
    size_t pos = s.find_first_of(':');
    if (pos == std::string::npos){
        return false;
    }

    label = s.substr(0, pos);
    data = s.substr(pos + 1);
    return true;
}

void split_to_line(const char* buffer, std::vector<std::string>& lines)
{
    char* p = (char*)buffer;
    std::string temp;
    while (*p){
        if (*p == '\r'){
            p++;
            continue;;
		}
		else if (*p == '\n'){
			lines.push_back(temp);
			temp = "";
		}
		else if (*p == '\\'){
			p++;
			while (*p == '\r' || *p == '\n') { p++; }
			continue;
		}
        else{
            temp += *p;
        }
        p++;
    }

    if (!temp.empty()){
        lines.push_back(temp);
    }
}

bool read_vector_data(const char* filename, std::vector<key_val_vec>& test_vec)
{
    FILE* fd = fopen(filename, "rb");
    if (!fd){
        return false;
    }

    uint32_t fsize = 0;
    fseek(fd, 0, SEEK_END);
    fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    uint8_t* buffer = new uint8_t[fsize +1];
    memset(buffer, 0, fsize + 1);
    (void)fread(buffer, fsize, 1, fd);
    fclose(fd);

    std::vector<std::string> lines;
    split_to_line((const char*) buffer, lines);
    delete[] buffer;
    buffer = NULL;

    key_val_vec kp_list;
    for (size_t i = 0; i < lines.size(); i++){
        /* printf("line: [%s]\n", lines[i].c_str()); */

        if (lines[i].empty()){
            if (!kp_list.empty()){
                test_vec.push_back(kp_list);
                kp_list.clear();
            }
            continue;
        }

        if (lines[i][0] == '#'){
            continue;
        }

        std::string label;
        std::string data;
        if (!parse_label_data(lines[i], label, data)){
            return false;
        }
        /* printf("[%s]:[%s]\n", label.c_str(), data.c_str()); */

        key_val_pair kp;
        kp.label = label;
        kp.data = data;
        kp_list.push_back(kp);
    }

    if (!kp_list.empty()){
        if (!kp_list.empty()){
            test_vec.push_back(kp_list);
        }
    }

    return true;
}

std::string trim(std::string s)
{
    if (s.empty())
        return s;
 
    s.erase(0,s.find_first_not_of(0x20));
    s.erase(s.find_last_not_of(0x20) + 1);
    s.erase(0,s.find_first_not_of('\r'));  
    s.erase(s.find_last_not_of('\r') + 1);
    s.erase(0,s.find_first_not_of('\n'));  
    s.erase(s.find_last_not_of('\n') + 1);

    return s;
}

bool get_key_val_pair(std::vector<key_val_vec>& test_vec, size_t index, std::string key, std::string& val){
    if (index >= test_vec.size()){
        return false;
    }

    key_val_vec k = test_vec[index];
    for (size_t i = 0 ;i < k.size(); i++){
        if (trim(k[i].label) == key){
            std::string s = trim(k[i].data);
            if (s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')){
                uint8_t* output = NULL;
                uint32_t output_len = 0;
                 if (!_hexstring_to_binary((char* )(s.substr(2).c_str()), &output, &output_len)){
                     return false;
                 }
                 val = std::string((char*)output, output_len);
                 _hexstring_to_binary_free(&output);
                 output = NULL;
                 return true;
            }
            else{
                val = s;
                return true;
            }
        }
    }

    return false;
}