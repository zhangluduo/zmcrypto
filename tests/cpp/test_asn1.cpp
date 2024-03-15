
#include "test_asn1.h"
#include "../../src/asn1.h"
#include "format_output.h"

#include <string>
#include <stack>
#include <vector>

uint8_t baidu_cert_der[] = 
{
    /*           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f*/
    /* 000 */ 0x30, 0x82, 0x09, 0xe8, 0x30, 0x82, 0x08, 0xd0, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x0c, 0x55,
    /* 001 */ 0xe6, 0xac, 0xae, 0xd1, 0xf8, 0xa4, 0x30, 0xf9, 0xa9, 0x38, 0xc5, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    /* 002 */ 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x50, 0x31, 0x0b, 0x30, 0x09,
    /* 003 */ 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x42, 0x45, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,
    /* 004 */ 0x04, 0x0a, 0x13, 0x10, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x6e,
    /* 005 */ 0x76, 0x2d, 0x73, 0x61, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1d, 0x47,
    /* 006 */ 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x53, 0x69, 0x67, 0x6e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x4f, 0x56,
    /* 007 */ 0x20, 0x53, 0x53, 0x4c, 0x20, 0x43, 0x41, 0x20, 0x32, 0x30, 0x31, 0x38, 0x30, 0x1e, 0x17, 0x0d,
    /* 008 */ 0x32, 0x33, 0x30, 0x37, 0x30, 0x36, 0x30, 0x31, 0x35, 0x31, 0x30, 0x36, 0x5a, 0x17, 0x0d, 0x32,
    /* 009 */ 0x34, 0x30, 0x38, 0x30, 0x36, 0x30, 0x31, 0x35, 0x31, 0x30, 0x35, 0x5a, 0x30, 0x81, 0x80, 0x31,
    /* 010 */ 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4e, 0x31, 0x10, 0x30, 0x0e,
    /* 011 */ 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x62, 0x65, 0x69, 0x6a, 0x69, 0x6e, 0x67, 0x31, 0x10,
    /* 012 */ 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x62, 0x65, 0x69, 0x6a, 0x69, 0x6e, 0x67,
    /* 013 */ 0x31, 0x39, 0x30, 0x37, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x30, 0x42, 0x65, 0x69, 0x6a, 0x69,
    /* 014 */ 0x6e, 0x67, 0x20, 0x42, 0x61, 0x69, 0x64, 0x75, 0x20, 0x4e, 0x65, 0x74, 0x63, 0x6f, 0x6d, 0x20,
    /* 015 */ 0x53, 0x63, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6e, 0x6f, 0x6c, 0x6f,
    /* 016 */ 0x67, 0x79, 0x20, 0x43, 0x6f, 0x2e, 0x2c, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x12, 0x30, 0x10, 0x06,
    /* 017 */ 0x03, 0x55, 0x04, 0x03, 0x13, 0x09, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    /* 018 */ 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    /* 019 */ 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
    /* 020 */ 0xbb, 0x04, 0xbb, 0x84, 0x76, 0x58, 0x07, 0xb4, 0x5a, 0x88, 0x54, 0xe0, 0x6a, 0x56, 0xbc, 0xe5,
    /* 021 */ 0xd4, 0x8d, 0x3e, 0x1e, 0xb9, 0x28, 0xe0, 0xd7, 0x01, 0x8f, 0x38, 0x2b, 0x41, 0xb2, 0x59, 0x7d,
    /* 022 */ 0xf0, 0xac, 0x27, 0xb4, 0x26, 0x24, 0x14, 0x38, 0xfe, 0x4c, 0xea, 0x3b, 0x49, 0x51, 0xf7, 0xe9,
    /* 023 */ 0x5b, 0x40, 0xf7, 0x3f, 0xa6, 0xc8, 0xda, 0x0f, 0x02, 0x6e, 0x25, 0x8b, 0x47, 0x91, 0xb8, 0x2e,
    /* 024 */ 0x9e, 0x00, 0x21, 0x19, 0x1d, 0x18, 0x00, 0xfc, 0xde, 0x04, 0xfd, 0x26, 0x79, 0x39, 0x5d, 0xf2,
    /* 025 */ 0x90, 0xbc, 0x80, 0x9d, 0xa8, 0x7c, 0xb2, 0x91, 0x89, 0x89, 0xd8, 0x40, 0x2f, 0xe5, 0xd2, 0xa7,
    /* 026 */ 0xf3, 0x5e, 0x6d, 0x48, 0x2b, 0xc5, 0x1f, 0x0a, 0xb1, 0xe0, 0x8e, 0x8c, 0x76, 0xff, 0xbc, 0xd1,
    /* 027 */ 0x67, 0x0a, 0xd2, 0x49, 0xd6, 0x09, 0xee, 0x26, 0x03, 0x02, 0xf3, 0xcc, 0xcd, 0xea, 0x8a, 0xd5,
    /* 028 */ 0x31, 0xa8, 0x2d, 0x8f, 0x03, 0xfd, 0x5e, 0xfc, 0xe4, 0x3a, 0xc6, 0x89, 0x67, 0x99, 0x4c, 0xce,
    /* 029 */ 0x98, 0x6d, 0xfa, 0x84, 0x0d, 0x0e, 0x53, 0x8b, 0xe6, 0x63, 0x52, 0xc5, 0x9b, 0x4a, 0xa9, 0xab,
    /* 030 */ 0xa3, 0x22, 0x35, 0x99, 0x0d, 0xee, 0x19, 0xff, 0x9b, 0x2d, 0xf5, 0xa4, 0x77, 0xf2, 0xec, 0x10,
    /* 031 */ 0x80, 0xf4, 0xab, 0x82, 0xb9, 0xd1, 0x7e, 0x36, 0x1f, 0x0e, 0x9f, 0x9b, 0x19, 0xa0, 0xf5, 0xc3,
    /* 032 */ 0x57, 0xdd, 0x88, 0xbb, 0xce, 0xe1, 0x90, 0x9c, 0x3f, 0x4b, 0xba, 0xdd, 0x3a, 0xa9, 0x41, 0xb3,
    /* 033 */ 0xdd, 0x86, 0x4d, 0xc2, 0xc2, 0xb7, 0xe8, 0xff, 0x37, 0x13, 0xc0, 0x04, 0x89, 0x43, 0x44, 0x38,
    /* 034 */ 0x11, 0xe6, 0xa3, 0x96, 0xf7, 0x09, 0x22, 0x21, 0x2f, 0x2c, 0x4e, 0x0e, 0x7e, 0xe5, 0xd8, 0x5c,
    /* 035 */ 0xbb, 0x00, 0x44, 0x5b, 0xaf, 0xde, 0xe4, 0xb3, 0xb0, 0xf0, 0x3c, 0xb6, 0x38, 0x45, 0x49, 0x5d,
    /* 036 */ 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x06, 0x8f, 0x30, 0x82, 0x06, 0x8b, 0x30, 0x0e, 0x06,
    /* 037 */ 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x81, 0x8e,
    /* 038 */ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x81, 0x81, 0x30, 0x7f, 0x30,
    /* 039 */ 0x44, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x38, 0x68, 0x74, 0x74,
    /* 040 */ 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61,
    /* 041 */ 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74,
    /* 042 */ 0x2f, 0x67, 0x73, 0x72, 0x73, 0x61, 0x6f, 0x76, 0x73, 0x73, 0x6c, 0x63, 0x61, 0x32, 0x30, 0x31,
    /* 043 */ 0x38, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x37, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    /* 044 */ 0x01, 0x86, 0x2b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x67,
    /* 045 */ 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x73,
    /* 046 */ 0x72, 0x73, 0x61, 0x6f, 0x76, 0x73, 0x73, 0x6c, 0x63, 0x61, 0x32, 0x30, 0x31, 0x38, 0x30, 0x56,
    /* 047 */ 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x4f, 0x30, 0x4d, 0x30, 0x41, 0x06, 0x09, 0x2b, 0x06, 0x01,
    /* 048 */ 0x04, 0x01, 0xa0, 0x32, 0x01, 0x14, 0x30, 0x34, 0x30, 0x32, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    /* 049 */ 0x05, 0x07, 0x02, 0x01, 0x16, 0x26, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
    /* 050 */ 0x77, 0x2e, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
    /* 051 */ 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x72, 0x79, 0x2f, 0x30, 0x08, 0x06, 0x06,
    /* 052 */ 0x67, 0x81, 0x0c, 0x01, 0x02, 0x02, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
    /* 053 */ 0x00, 0x30, 0x3f, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x38, 0x30, 0x36, 0x30, 0x34, 0xa0, 0x32,
    /* 054 */ 0xa0, 0x30, 0x86, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x2e, 0x67,
    /* 055 */ 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x73,
    /* 056 */ 0x72, 0x73, 0x61, 0x6f, 0x76, 0x73, 0x73, 0x6c, 0x63, 0x61, 0x32, 0x30, 0x31, 0x38, 0x2e, 0x63,
    /* 057 */ 0x72, 0x6c, 0x30, 0x82, 0x03, 0x61, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x82, 0x03, 0x58, 0x30,
    /* 058 */ 0x82, 0x03, 0x54, 0x82, 0x09, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0c,
    /* 059 */ 0x62, 0x61, 0x69, 0x66, 0x75, 0x62, 0x61, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0c, 0x77, 0x77,
    /* 060 */ 0x77, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6e, 0x82, 0x10, 0x77, 0x77, 0x77, 0x2e,
    /* 061 */ 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x63, 0x6e, 0x82, 0x0f, 0x6d, 0x63,
    /* 062 */ 0x74, 0x2e, 0x79, 0x2e, 0x6e, 0x75, 0x6f, 0x6d, 0x69, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0b, 0x61,
    /* 063 */ 0x70, 0x6f, 0x6c, 0x6c, 0x6f, 0x2e, 0x61, 0x75, 0x74, 0x6f, 0x82, 0x06, 0x64, 0x77, 0x7a, 0x2e,
    /* 064 */ 0x63, 0x6e, 0x82, 0x0b, 0x2a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82,
    /* 065 */ 0x0e, 0x2a, 0x2e, 0x62, 0x61, 0x69, 0x66, 0x75, 0x62, 0x61, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x82,
    /* 066 */ 0x11, 0x2a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x2e, 0x63,
    /* 067 */ 0x6f, 0x6d, 0x82, 0x0e, 0x2a, 0x2e, 0x62, 0x64, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x2e, 0x63,
    /* 068 */ 0x6f, 0x6d, 0x82, 0x0b, 0x2a, 0x2e, 0x62, 0x64, 0x69, 0x6d, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x82,
    /* 069 */ 0x0c, 0x2a, 0x2e, 0x68, 0x61, 0x6f, 0x31, 0x32, 0x33, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0b, 0x2a,
    /* 070 */ 0x2e, 0x6e, 0x75, 0x6f, 0x6d, 0x69, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0d, 0x2a, 0x2e, 0x63, 0x68,
    /* 071 */ 0x75, 0x61, 0x6e, 0x6b, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0d, 0x2a, 0x2e, 0x74, 0x72, 0x75,
    /* 072 */ 0x73, 0x74, 0x67, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0f, 0x2a, 0x2e, 0x62, 0x63, 0x65, 0x2e,
    /* 073 */ 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x10, 0x2a, 0x2e, 0x65, 0x79, 0x75,
    /* 074 */ 0x6e, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0f, 0x2a, 0x2e, 0x6d,
    /* 075 */ 0x61, 0x70, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0f, 0x2a, 0x2e,
    /* 076 */ 0x6d, 0x62, 0x64, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x11, 0x2a,
    /* 077 */ 0x2e, 0x66, 0x61, 0x6e, 0x79, 0x69, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d,
    /* 078 */ 0x82, 0x0e, 0x2a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x62, 0x63, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
    /* 079 */ 0x82, 0x0c, 0x2a, 0x2e, 0x6d, 0x69, 0x70, 0x63, 0x64, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x10,
    /* 080 */ 0x2a, 0x2e, 0x6e, 0x65, 0x77, 0x73, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d,
    /* 081 */ 0x82, 0x0e, 0x2a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x70, 0x63, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
    /* 082 */ 0x82, 0x0c, 0x2a, 0x2e, 0x61, 0x69, 0x70, 0x61, 0x67, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0b,
    /* 083 */ 0x2a, 0x2e, 0x61, 0x69, 0x70, 0x61, 0x67, 0x65, 0x2e, 0x63, 0x6e, 0x82, 0x0d, 0x2a, 0x2e, 0x62,
    /* 084 */ 0x63, 0x65, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x10, 0x2a, 0x2e, 0x73, 0x61,
    /* 085 */ 0x66, 0x65, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0e, 0x2a, 0x2e,
    /* 086 */ 0x69, 0x6d, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x12, 0x2a, 0x2e,
    /* 087 */ 0x62, 0x61, 0x69, 0x64, 0x75, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x63, 0x6f, 0x6d,
    /* 088 */ 0x82, 0x0b, 0x2a, 0x2e, 0x64, 0x6c, 0x6e, 0x65, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0b, 0x2a,
    /* 089 */ 0x2e, 0x64, 0x6c, 0x6e, 0x65, 0x6c, 0x2e, 0x6f, 0x72, 0x67, 0x82, 0x12, 0x2a, 0x2e, 0x64, 0x75,
    /* 090 */ 0x65, 0x72, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0e,
    /* 091 */ 0x2a, 0x2e, 0x73, 0x75, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x08,
    /* 092 */ 0x2a, 0x2e, 0x39, 0x31, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x12, 0x2a, 0x2e, 0x68, 0x61, 0x6f, 0x31,
    /* 093 */ 0x32, 0x33, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0d, 0x2a, 0x2e,
    /* 094 */ 0x61, 0x70, 0x6f, 0x6c, 0x6c, 0x6f, 0x2e, 0x61, 0x75, 0x74, 0x6f, 0x82, 0x12, 0x2a, 0x2e, 0x78,
    /* 095 */ 0x75, 0x65, 0x73, 0x68, 0x75, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82,
    /* 096 */ 0x11, 0x2a, 0x2e, 0x62, 0x6a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x62, 0x63, 0x65, 0x2e, 0x63,
    /* 097 */ 0x6f, 0x6d, 0x82, 0x11, 0x2a, 0x2e, 0x67, 0x7a, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x62, 0x63,
    /* 098 */ 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0e, 0x2a, 0x2e, 0x73, 0x6d, 0x61, 0x72, 0x74, 0x61, 0x70,
    /* 099 */ 0x70, 0x73, 0x2e, 0x63, 0x6e, 0x82, 0x0d, 0x2a, 0x2e, 0x62, 0x64, 0x74, 0x6a, 0x72, 0x63, 0x76,
    /* 100 */ 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x0c, 0x2a, 0x2e, 0x68, 0x61, 0x6f, 0x32, 0x32, 0x32, 0x2e, 0x63,
    /* 101 */ 0x6f, 0x6d, 0x82, 0x0c, 0x2a, 0x2e, 0x68, 0x61, 0x6f, 0x6b, 0x61, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
    /* 102 */ 0x82, 0x0f, 0x2a, 0x2e, 0x70, 0x61, 0x65, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f,
    /* 103 */ 0x6d, 0x82, 0x11, 0x2a, 0x2e, 0x76, 0x64, 0x2e, 0x62, 0x64, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63,
    /* 104 */ 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x11, 0x2a, 0x2e, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x2e, 0x62, 0x61,
    /* 105 */ 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x12, 0x63, 0x6c, 0x69, 0x63, 0x6b, 0x2e, 0x68,
    /* 106 */ 0x6d, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x10, 0x6c, 0x6f, 0x67,
    /* 107 */ 0x2e, 0x68, 0x6d, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x10, 0x63,
    /* 108 */ 0x6d, 0x2e, 0x70, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x82,
    /* 109 */ 0x10, 0x77, 0x6e, 0x2e, 0x70, 0x6f, 0x73, 0x2e, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f,
    /* 110 */ 0x6d, 0x82, 0x14, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x61, 0x6e, 0x2e, 0x62, 0x61,
    /* 111 */ 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16,
    /* 112 */ 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06,
    /* 113 */ 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30,
    /* 114 */ 0x16, 0x80, 0x14, 0xf8, 0xef, 0x7f, 0xf2, 0xcd, 0x78, 0x67, 0xa8, 0xde, 0x6f, 0x8f, 0x24, 0x8d,
    /* 115 */ 0x88, 0xf1, 0x87, 0x03, 0x02, 0xb3, 0xeb, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
    /* 116 */ 0x04, 0x14, 0xed, 0x73, 0xab, 0xf9, 0x20, 0xbe, 0x7a, 0x19, 0x9f, 0x59, 0x1f, 0xb2, 0x9f, 0xf2,
    /* 117 */ 0x3f, 0x2f, 0x3f, 0x91, 0x84, 0x12, 0x30, 0x82, 0x01, 0x7e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
    /* 118 */ 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02, 0x04, 0x82, 0x01, 0x6e, 0x04, 0x82, 0x01, 0x6a, 0x01, 0x68,
    /* 119 */ 0x00, 0x76, 0x00, 0x48, 0xb0, 0xe3, 0x6b, 0xda, 0xa6, 0x47, 0x34, 0x0f, 0xe5, 0x6a, 0x02, 0xfa,
    /* 120 */ 0x9d, 0x30, 0xeb, 0x1c, 0x52, 0x01, 0xcb, 0x56, 0xdd, 0x2c, 0x81, 0xd9, 0xbb, 0xbf, 0xab, 0x39,
    /* 121 */ 0xd8, 0x84, 0x73, 0x00, 0x00, 0x01, 0x89, 0x28, 0xe5, 0x70, 0x01, 0x00, 0x00, 0x04, 0x03, 0x00,
    /* 122 */ 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xed, 0x1a, 0xf4, 0x5f, 0x4a, 0xcc, 0x2b, 0xff, 0x57, 0xdf,
    /* 123 */ 0xe5, 0xb8, 0xcb, 0xf9, 0x24, 0x5c, 0xb7, 0x7e, 0x14, 0x7b, 0xa3, 0xda, 0x46, 0xc0, 0xd8, 0xbc,
    /* 124 */ 0x68, 0x69, 0x89, 0x87, 0xa3, 0x83, 0x02, 0x20, 0x5f, 0xf6, 0x82, 0x83, 0xd3, 0xa0, 0xe4, 0x46,
    /* 125 */ 0x5b, 0x54, 0xba, 0x3e, 0x66, 0xca, 0xd4, 0xf6, 0xcd, 0xc8, 0x26, 0xeb, 0x18, 0xcd, 0x96, 0x23,
    /* 126 */ 0x01, 0x22, 0x6c, 0xcc, 0x4c, 0xf0, 0x67, 0x5a, 0x00, 0x77, 0x00, 0xee, 0xcd, 0xd0, 0x64, 0xd5,
    /* 127 */ 0xdb, 0x1a, 0xce, 0xc5, 0x5c, 0xb7, 0x9d, 0xb4, 0xcd, 0x13, 0xa2, 0x32, 0x87, 0x46, 0x7c, 0xbc,
    /* 128 */ 0xec, 0xde, 0xc3, 0x51, 0x48, 0x59, 0x46, 0x71, 0x1f, 0xb5, 0x9b, 0x00, 0x00, 0x01, 0x89, 0x28,
    /* 129 */ 0xe5, 0x70, 0x1d, 0x00, 0x00, 0x04, 0x03, 0x00, 0x48, 0x30, 0x46, 0x02, 0x21, 0x00, 0xbd, 0x1d,
    /* 130 */ 0xc3, 0x18, 0x2a, 0x7e, 0x78, 0x1e, 0x2b, 0xd2, 0x6e, 0x11, 0xf4, 0xc2, 0xe5, 0xad, 0xc1, 0x36,
    /* 130 */ 0x87, 0x62, 0xdb, 0x88, 0xbc, 0x90, 0xfc, 0x22, 0x13, 0xc5, 0xfb, 0x32, 0x7d, 0xfe, 0x02, 0x21,
    /* 131 */ 0x00, 0x80, 0x8c, 0x9e, 0x88, 0x86, 0xa1, 0xc7, 0x3a, 0x14, 0x62, 0x0c, 0x21, 0x89, 0x8c, 0x77,
    /* 132 */ 0xba, 0x7b, 0x24, 0x94, 0x97, 0x31, 0x90, 0xa9, 0x15, 0x74, 0xa2, 0x6c, 0x2c, 0x33, 0x83, 0x52,
    /* 133 */ 0x2d, 0x00, 0x75, 0x00, 0xda, 0xb6, 0xbf, 0x6b, 0x3f, 0xb5, 0xb6, 0x22, 0x9f, 0x9b, 0xc2, 0xbb,
    /* 134 */ 0x5c, 0x6b, 0xe8, 0x70, 0x91, 0x71, 0x6c, 0xbb, 0x51, 0x84, 0x85, 0x34, 0xbd, 0xa4, 0x3d, 0x30,
    /* 135 */ 0x48, 0xd7, 0xfb, 0xab, 0x00, 0x00, 0x01, 0x89, 0x28, 0xe5, 0x6d, 0x57, 0x00, 0x00, 0x04, 0x03,
    /* 136 */ 0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x54, 0x6d, 0x6a, 0x69, 0xea, 0xe0, 0xa3, 0x58, 0xf9, 0x17,
    /* 137 */ 0xd5, 0xad, 0xe4, 0x77, 0x36, 0xa3, 0x7b, 0x33, 0x8d, 0xc3, 0x95, 0x30, 0x76, 0x7e, 0xe5, 0xfb,
    /* 138 */ 0x1c, 0xa9, 0x8c, 0x4e, 0x9b, 0x77, 0x02, 0x20, 0x1b, 0x61, 0x8a, 0xf2, 0x91, 0xfe, 0xe5, 0x4a,
    /* 149 */ 0x99, 0x4d, 0x32, 0xb1, 0x37, 0x2a, 0x82, 0x46, 0x88, 0x89, 0x0d, 0x7e, 0xeb, 0x01, 0x7c, 0xf1,
    /* 140 */ 0x3b, 0x6d, 0x9a, 0x21, 0x19, 0x24, 0x05, 0xc0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    /* 141 */ 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x19, 0x5a, 0x67, 0x50,
    /* 142 */ 0x43, 0xb1, 0xac, 0x7a, 0x93, 0xa8, 0x68, 0x18, 0x72, 0x8b, 0x40, 0x7e, 0xa6, 0x75, 0xde, 0xac,
    /* 143 */ 0x21, 0xfc, 0xc9, 0x41, 0x16, 0x20, 0x4b, 0xf3, 0x8c, 0x0b, 0xb9, 0x47, 0x45, 0xae, 0xf8, 0x5d,
    /* 144 */ 0x79, 0xf6, 0x43, 0x35, 0x26, 0x01, 0x98, 0xf0, 0xb9, 0x86, 0x3e, 0x29, 0x01, 0xf1, 0xdf, 0xb0,
    /* 145 */ 0x72, 0xb5, 0xae, 0x78, 0xd2, 0xdf, 0x61, 0xb6, 0x78, 0x67, 0x8a, 0xc9, 0x77, 0x9a, 0xde, 0xe0,
    /* 146 */ 0xe4, 0x41, 0x2f, 0x9c, 0x1e, 0xe5, 0x3b, 0x7c, 0x97, 0x3f, 0x42, 0x2f, 0xad, 0xe3, 0x49, 0x7f,
    /* 147 */ 0x9d, 0x2b, 0x02, 0x88, 0x90, 0x69, 0x25, 0x03, 0x01, 0x14, 0xb9, 0xb5, 0xcb, 0x0f, 0x59, 0x3d,
    /* 148 */ 0x2d, 0x97, 0x3d, 0x02, 0xd5, 0x51, 0x90, 0x69, 0x0c, 0x81, 0x10, 0x22, 0xda, 0xc6, 0x51, 0xef,
    /* 159 */ 0x48, 0x0c, 0xd2, 0x4f, 0xde, 0x61, 0xf2, 0x6a, 0x87, 0x15, 0xa5, 0x6d, 0x71, 0x8e, 0x37, 0x02,
    /* 150 */ 0xa2, 0x85, 0x0f, 0x1e, 0x19, 0x75, 0xa3, 0x80, 0x2e, 0x6a, 0x1a, 0xa2, 0x02, 0x8c, 0x2f, 0xec,
    /* 151 */ 0xbd, 0x3d, 0x81, 0x03, 0x3f, 0x8a, 0xc0, 0xa0, 0xe6, 0xb4, 0x0e, 0x08, 0x57, 0xcb, 0x00, 0x1c,
    /* 152 */ 0x8a, 0xb7, 0x1b, 0x8f, 0x38, 0x71, 0x9a, 0x8d, 0xc0, 0x71, 0x0c, 0x3f, 0xbc, 0xd4, 0xbe, 0x56,
    /* 153 */ 0x9d, 0xf7, 0x18, 0xc1, 0xaa, 0xbe, 0xe4, 0xdf, 0x1a, 0x86, 0xe2, 0x62, 0x6f, 0x23, 0x86, 0x30,
    /* 154 */ 0x54, 0x78, 0x2d, 0x47, 0x1f, 0xb4, 0xad, 0x05, 0x29, 0x73, 0x24, 0x98, 0x14, 0xa0, 0x19, 0xc0,
    /* 155 */ 0x02, 0xfd, 0x90, 0x90, 0x4e, 0x62, 0x5c, 0xe8, 0x4d, 0x31, 0x89, 0xc3, 0xe8, 0x8b, 0x9e, 0x73,
    /* 156 */ 0x59, 0x3b, 0x98, 0x91, 0xca, 0x47, 0xa5, 0x05, 0x5b, 0xc5, 0x1e, 0x8f, 0x85, 0x39, 0x0e, 0xce,
    /* 157 */ 0xb5, 0x26, 0x0a, 0x80, 0x4e, 0x9f, 0x08, 0x4a, 0x11, 0x49, 0x13, 0x63
};

uint32_t baidu_cert_der_len = sizeof(baidu_cert_der);

uint8_t google_cert_der[] = 
{
    /*           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f*/
    /* 000 */ 0x30, 0x82, 0x04, 0x88, 0x30, 0x82, 0x03, 0x70, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00,
    /* 001 */ 0xd3, 0xd7, 0xb5, 0x08, 0x90, 0xb2, 0x9b, 0x7d, 0x12, 0xc2, 0x05, 0x80, 0x8f, 0x0c, 0x0e, 0xb4,
    /* 002 */ 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
    /* 003 */ 0x46, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x22,
    /* 004 */ 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x19, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20,
    /* 005 */ 0x54, 0x72, 0x75, 0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x4c,
    /* 006 */ 0x4c, 0x43, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x47, 0x54, 0x53,
    /* 007 */ 0x20, 0x43, 0x41, 0x20, 0x31, 0x43, 0x33, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x39, 0x31,
    /* 008 */ 0x38, 0x30, 0x38, 0x32, 0x35, 0x31, 0x34, 0x5a, 0x17, 0x0d, 0x32, 0x33, 0x31, 0x32, 0x31, 0x31,
    /* 009 */ 0x30, 0x38, 0x32, 0x35, 0x31, 0x33, 0x5a, 0x30, 0x19, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55,
    /* 010 */ 0x04, 0x03, 0x13, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63,
    /* 011 */ 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    /* 012 */ 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x4f, 0xfe, 0x99,
    /* 013 */ 0x5e, 0x81, 0x5b, 0xa9, 0xea, 0xbb, 0x00, 0xee, 0x5f, 0xee, 0x7d, 0x7c, 0xa6, 0x6d, 0x16, 0xea,
    /* 014 */ 0xcf, 0x60, 0x9b, 0xc9, 0xd1, 0x24, 0x6b, 0x95, 0x7e, 0x86, 0x90, 0x6d, 0xa4, 0xcc, 0xc4, 0x7a,
    /* 015 */ 0x09, 0x61, 0x11, 0xfc, 0xa3, 0x87, 0x6a, 0x53, 0x31, 0xb8, 0x21, 0x7a, 0x7c, 0x75, 0x5f, 0xdf,
    /* 016 */ 0x04, 0x07, 0x75, 0xa2, 0x7f, 0xc6, 0xcd, 0xe2, 0xad, 0x0d, 0x53, 0xab, 0xfa, 0xa3, 0x82, 0x02,
    /* 017 */ 0x67, 0x30, 0x82, 0x02, 0x63, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04,
    /* 018 */ 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
    /* 019 */ 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d,
    /* 020 */ 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    /* 021 */ 0x16, 0x04, 0x14, 0x33, 0x0d, 0x47, 0x32, 0xc8, 0x34, 0x1a, 0x0c, 0x6e, 0x2e, 0x91, 0xb4, 0x0f,
    /* 022 */ 0x31, 0x9e, 0xff, 0x09, 0x62, 0xb3, 0x0b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    /* 023 */ 0x30, 0x16, 0x80, 0x14, 0x8a, 0x74, 0x7f, 0xaf, 0x85, 0xcd, 0xee, 0x95, 0xcd, 0x3d, 0x9c, 0xd0,
    /* 024 */ 0xe2, 0x46, 0x14, 0xf3, 0x71, 0x35, 0x1d, 0x27, 0x30, 0x6a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    /* 025 */ 0x05, 0x07, 0x01, 0x01, 0x04, 0x5e, 0x30, 0x5c, 0x30, 0x27, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    /* 026 */ 0x05, 0x07, 0x30, 0x01, 0x86, 0x1b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73,
    /* 027 */ 0x70, 0x2e, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x67, 0x74, 0x73, 0x31, 0x63,
    /* 028 */ 0x33, 0x30, 0x31, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x25, 0x68,
    /* 029 */ 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x72,
    /* 030 */ 0x65, 0x70, 0x6f, 0x2f, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2f, 0x67, 0x74, 0x73, 0x31, 0x63, 0x33,
    /* 031 */ 0x2e, 0x64, 0x65, 0x72, 0x30, 0x19, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x12, 0x30, 0x10, 0x82,
    /* 032 */ 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    /* 033 */ 0x21, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x1a, 0x30, 0x18, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81,
    /* 034 */ 0x0c, 0x01, 0x02, 0x01, 0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02,
    /* 035 */ 0x05, 0x03, 0x30, 0x3c, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x35, 0x30, 0x33, 0x30, 0x31, 0xa0,
    /* 036 */ 0x2f, 0xa0, 0x2d, 0x86, 0x2b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c, 0x73,
    /* 037 */ 0x2e, 0x70, 0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x67, 0x74, 0x73, 0x31, 0x63, 0x33,
    /* 038 */ 0x2f, 0x7a, 0x64, 0x41, 0x54, 0x74, 0x30, 0x45, 0x78, 0x5f, 0x46, 0x6b, 0x2e, 0x63, 0x72, 0x6c,
    /* 039 */ 0x30, 0x82, 0x01, 0x04, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02,
    /* 040 */ 0x04, 0x81, 0xf5, 0x04, 0x81, 0xf2, 0x00, 0xf0, 0x00, 0x76, 0x00, 0xad, 0xf7, 0xbe, 0xfa, 0x7c,
    /* 041 */ 0xff, 0x10, 0xc8, 0x8b, 0x9d, 0x3d, 0x9c, 0x1e, 0x3e, 0x18, 0x6a, 0xb4, 0x67, 0x29, 0x5d, 0xcf,
    /* 042 */ 0xb1, 0x0c, 0x24, 0xca, 0x85, 0x86, 0x34, 0xeb, 0xdc, 0x82, 0x8a, 0x00, 0x00, 0x01, 0x8a, 0xa7,
    /* 043 */ 0x9b, 0xbb, 0xeb, 0x00, 0x00, 0x04, 0x03, 0x00, 0x47, 0x30, 0x45, 0x02, 0x20, 0x12, 0x99, 0x2a,
    /* 044 */ 0x1b, 0x4a, 0xed, 0x3d, 0x4e, 0x2b, 0x9b, 0xc7, 0xba, 0xea, 0x25, 0x0f, 0xca, 0x4b, 0xe2, 0x33,
    /* 045 */ 0x25, 0xf1, 0x2f, 0x80, 0x2a, 0x70, 0x1b, 0x88, 0x96, 0x15, 0x1d, 0x0b, 0x18, 0x02, 0x21, 0x00,
    /* 046 */ 0x9d, 0x73, 0x7f, 0x51, 0xf1, 0xb8, 0x8f, 0xa5, 0x60, 0x0c, 0xdd, 0x91, 0xa4, 0xf5, 0x92, 0x55,
    /* 047 */ 0x76, 0x71, 0x6a, 0x1f, 0xe5, 0xf7, 0xae, 0xfd, 0xc8, 0xa5, 0x47, 0x58, 0x30, 0xc0, 0x53, 0x0e,
    /* 048 */ 0x00, 0x76, 0x00, 0xb7, 0x3e, 0xfb, 0x24, 0xdf, 0x9c, 0x4d, 0xba, 0x75, 0xf2, 0x39, 0xc5, 0xba,
    /* 049 */ 0x58, 0xf4, 0x6c, 0x5d, 0xfc, 0x42, 0xcf, 0x7a, 0x9f, 0x35, 0xc4, 0x9e, 0x1d, 0x09, 0x81, 0x25,
    /* 050 */ 0xed, 0xb4, 0x99, 0x00, 0x00, 0x01, 0x8a, 0xa7, 0x9b, 0xbb, 0xc7, 0x00, 0x00, 0x04, 0x03, 0x00,
    /* 051 */ 0x47, 0x30, 0x45, 0x02, 0x20, 0x41, 0x27, 0x2e, 0xa4, 0x20, 0x1c, 0xa1, 0x20, 0x5f, 0x6c, 0x94,
    /* 052 */ 0x2a, 0x0c, 0x65, 0xa3, 0xeb, 0x14, 0x1a, 0x25, 0x91, 0x25, 0xe9, 0x00, 0xad, 0xfc, 0x90, 0x2c,
    /* 053 */ 0x8b, 0x5b, 0xf6, 0xb2, 0xe9, 0x02, 0x21, 0x00, 0x8f, 0xe9, 0x5f, 0x45, 0x29, 0x7d, 0x7d, 0x07,
    /* 054 */ 0x54, 0xe7, 0x14, 0x96, 0x36, 0xfb, 0x66, 0xff, 0x71, 0x21, 0x9a, 0xec, 0x94, 0x5f, 0xbc, 0xbd,
    /* 055 */ 0xa4, 0x33, 0x5d, 0xfd, 0x4f, 0x79, 0x9d, 0xf4, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    /* 056 */ 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0xea, 0x26, 0x99, 0x60,
    /* 057 */ 0x80, 0x8b, 0x58, 0x02, 0x9b, 0xda, 0x4e, 0xa8, 0xab, 0x1a, 0xb6, 0x78, 0xb3, 0x5b, 0xa1, 0xd0,
    /* 058 */ 0xc7, 0x17, 0xb5, 0x78, 0x4c, 0x0b, 0xde, 0x83, 0xd1, 0x7e, 0x32, 0x6d, 0xfe, 0x0c, 0xc9, 0x80,
    /* 059 */ 0xfe, 0x47, 0xd7, 0x57, 0x12, 0xb9, 0xd7, 0x73, 0x17, 0x8a, 0x7e, 0x8b, 0xa1, 0x45, 0x60, 0x12,
    /* 060 */ 0x5f, 0x98, 0x09, 0xe2, 0x0a, 0x28, 0x4e, 0x0d, 0x89, 0xfa, 0x54, 0x94, 0x2b, 0x37, 0x71, 0x3a,
    /* 061 */ 0x55, 0x70, 0x5e, 0x68, 0x13, 0xc7, 0x71, 0xad, 0xdc, 0xff, 0xed, 0xaa, 0x53, 0xfe, 0xf6, 0x0a,
    /* 062 */ 0x3d, 0x71, 0x33, 0xf4, 0x5e, 0xaf, 0x4f, 0x02, 0xde, 0x45, 0x03, 0xaa, 0xa9, 0x8b, 0xda, 0x40,
    /* 063 */ 0xe2, 0x55, 0x74, 0xfd, 0x5d, 0xeb, 0x96, 0x05, 0x72, 0x03, 0x3d, 0x06, 0x05, 0x8a, 0x79, 0x66,
    /* 064 */ 0x71, 0x66, 0xc1, 0x72, 0x88, 0x13, 0x03, 0x3c, 0xde, 0xbd, 0x36, 0x47, 0x8b, 0xc8, 0x7a, 0xb5,
    /* 065 */ 0x0b, 0x0a, 0xe7, 0xeb, 0xcd, 0xf8, 0xfc, 0x5f, 0x3f, 0xf4, 0xfe, 0x86, 0x66, 0x7b, 0xa1, 0x93,
    /* 066 */ 0xf2, 0x2e, 0x92, 0x6f, 0x19, 0x8c, 0x07, 0xd7, 0x62, 0xc3, 0x3b, 0xde, 0x37, 0xa7, 0x0e, 0x38,
    /* 067 */ 0x4a, 0xef, 0xe4, 0x8f, 0xfb, 0x79, 0xf6, 0xb0, 0x66, 0xf8, 0x23, 0x0f, 0x1f, 0x34, 0xaa, 0x08,
    /* 068 */ 0x73, 0x56, 0x0a, 0xe7, 0x6d, 0x03, 0x32, 0x33, 0x6f, 0x16, 0x68, 0x95, 0x1e, 0x30, 0x52, 0x75,
    /* 069 */ 0x33, 0x56, 0xc2, 0x32, 0x63, 0xc9, 0x9e, 0xf5, 0xf1, 0x26, 0x93, 0xe0, 0x66, 0xa1, 0x07, 0xb9,
    /* 070 */ 0x1b, 0xc3, 0x2c, 0xc3, 0x28, 0xf6, 0x5c, 0x7c, 0xe8, 0xa0, 0x9d, 0x89, 0x8c, 0x68, 0xe2, 0x70,
    /* 071 */ 0xc0, 0x6a, 0x34, 0x4d, 0xd6, 0x63, 0xbe, 0xa1, 0x1d, 0xa6, 0xe1, 0xb8, 0x18, 0xfe, 0xa6, 0xff,
    /* 072 */ 0x94, 0xa4, 0x05, 0x5e, 0x27, 0xce, 0x02, 0x2e, 0x27, 0xe2, 0xd1, 0x27 
};

uint32_t google_cert_der_len = sizeof(google_cert_der);

void helper_print_asn1_data(uint8_t* data, uint32_t dlen){
    for (int i = 0; i < dlen; i++) { printf ("%02x ", data[i]); }
    printf ("\n");
}

const char* tree_h_begin = "\xe2\x94\x9c"; /* ├ */
const char* tree_h_end   = "\xe2\x94\x80"; /* ─ */
const char* tree_v_begin = "\xe2\x94\x82"; /* │ */
const char* tree_v_end   = "\xe2\x94\x94"; /* └ */

void helper_print_asn1_ctx(struct asn1_ctx* ctx, uint32_t level, uint32_t offset){
    printf ("[%4d][%4d]:", offset, asn1_get_value_dlen(ctx));

    const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
    printf("%*s", level * 2, "");
    printf ("%s\n", s);

    uint32_t result;
    (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);
    if (result == 1){
        printf ("%*s:", 12, "");
        printf("%*s", level * 2, "");
        printf ("{\n");
    }
}

void helper_print_asn1_right_end(uint32_t level, uint32_t offset){
    printf ("%*s:", 12, "");
    printf("%*s", level * 2, "");
    printf ("}\n");
}

void test_asn1_case1()
{
    uint8_t der_data[] = {0x30};
    uint32_t der_len = 1;
    uint32_t copy = 0;

    struct asn1_ctx* ctx = asn1_ctx_new();
    asn1_ctx_init(ctx);
    
    zmerror err = asn1_parse_data(der_data, der_len, ctx, copy);
    if (ZMCRYPTO_ERR_ASN1_OUT_OF_DATA == err){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #1");
    return;

succ:
    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #1");
    return;
}

void test_asn1_case2()
{
    /*1 byte length (less than 128) */
    uint8_t der_data[] = {0x30, 0x7f,
        0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xdd
    };
    uint32_t der_len = 129;
    uint32_t copy = 0;

    struct asn1_ctx* ctx = asn1_ctx_new();
    asn1_ctx_init(ctx);
    
    zmerror err = asn1_parse_data(der_data, der_len, ctx, copy);
    if (ZMCRYPTO_IS_ERROR(err)){
        goto fail;
    }
    else{
        goto succ;
    }

fail:
    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #2");
    return;

succ:

    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #2");
    return;
}

void test_asn1_case3() {
    /*1 byte length (less than 128) */
    uint8_t der_data[] = {0x30, 0x7f,
        0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xdd
    };
    uint32_t der_len = 128;
    uint32_t copy = 0;

    struct asn1_ctx* ctx = asn1_ctx_new();
    asn1_ctx_init(ctx);
    
    zmerror err = asn1_parse_data(der_data, der_len, ctx, copy);
    if (ZMCRYPTO_ERR_ASN1_OUT_OF_DATA == err){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #3");
    return;

succ:

    asn1_ctx_free(ctx);
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #3");
    return;
}

void test_asn1_case4()
{ 
    uint8_t der_data[] = {
        0x30, 0x7f, /*127 byte value data*/
        0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcc, 0xdd,
        /*next parse position*/ /*1 byte value data*/
        0x30, 0x01, 0xee,
        /*next parse position*/
        0x30, 0x81, 0x80,/*128 byte value data*/
        0xeb, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee, 0xef
    };
    uint32_t der_len =  2 + 127 /* 129 */
                        + 3
                        + 3 + 128; /* 131 */
    uint32_t copy = 0;

    struct asn1_ctx* ctx = asn1_ctx_new();
    struct asn1_ctx* ctx2 = asn1_ctx_new();
    struct asn1_ctx* ctx3 = asn1_ctx_new();
    asn1_ctx_init(ctx);
    asn1_ctx_init(ctx2);
    asn1_ctx_init(ctx3);
    
    zmerror err = asn1_parse_data(der_data, der_len, ctx, copy);
    if (ZMCRYPTO_IS_ERROR(err)){
        goto fail;
    }

    if (asn1_get_tag_dlen(ctx) != 1 || zmcrypto_memcmp(asn1_get_tag_data(ctx), der_data, asn1_get_tag_dlen(ctx)) != 0){
        goto fail;
    }

    if (asn1_get_length_dlen(ctx) != 1 || zmcrypto_memcmp(asn1_get_length_data(ctx), der_data + 1, asn1_get_length_dlen(ctx)) != 0){
        goto fail;
    }

    if (asn1_get_value_dlen(ctx) != 127 || zmcrypto_memcmp(asn1_get_value_data(ctx), der_data + 2, asn1_get_value_dlen(ctx)) != 0){
        goto fail;
    }

    if (asn1_get_next_data(ctx) == NULL || asn1_get_next_dlen(ctx) == 0){
        goto fail;
    }

    if (asn1_get_next_dlen(ctx) != 134 || zmcrypto_memcmp(asn1_get_next_data(ctx), der_data + 129, asn1_get_next_dlen(ctx)) != 0){
        goto fail;
    }

    err = asn1_parse_data(asn1_get_next_data(ctx), asn1_get_next_dlen(ctx), ctx2, copy);
    if (ZMCRYPTO_IS_ERROR(err)){
        printf("line[%d]\n", __LINE__);
        goto fail;
    }

    if (asn1_get_tag_dlen(ctx2) != 1 || zmcrypto_memcmp(asn1_get_tag_data(ctx2), der_data + 129, asn1_get_tag_dlen(ctx2)) != 0){
        goto fail;
    }

    if (asn1_get_length_dlen(ctx2) != 1 || zmcrypto_memcmp(asn1_get_length_data(ctx2), der_data + 130, asn1_get_length_dlen(ctx2)) != 0){
        goto fail;
    }

    if (asn1_get_value_dlen(ctx2) != 1 || zmcrypto_memcmp(asn1_get_value_data(ctx2), der_data + 131, asn1_get_value_dlen(ctx2)) != 0){
        goto fail;
    }

    if (asn1_get_next_data(ctx2) == NULL || asn1_get_next_dlen(ctx2) == 0){
        goto fail;
    }
    if (asn1_get_next_dlen(ctx2) != 131 || zmcrypto_memcmp(asn1_get_next_data(ctx2), der_data + 129+3, asn1_get_next_dlen(ctx2)) != 0){
        goto fail;
    }

    err = asn1_parse_data(asn1_get_next_data(ctx2), asn1_get_next_dlen(ctx2), ctx3, copy);
    if (ZMCRYPTO_IS_ERROR(err)){
        printf("line[%d]\n", __LINE__);
        goto fail;
    }

    if (asn1_get_next_data(ctx3) != NULL || asn1_get_next_dlen(ctx3) != 0){
        printf("line[%d]\n", __LINE__);
        goto fail;
    }

    if (asn1_get_tag_dlen(ctx3) != 1 || zmcrypto_memcmp(asn1_get_tag_data(ctx3), der_data + (129+3), asn1_get_tag_dlen(ctx3)) != 0){
        goto fail;
    }

    if (asn1_get_length_dlen(ctx3) != 2 || zmcrypto_memcmp(asn1_get_length_data(ctx3), der_data + (129+3) + 1, asn1_get_length_dlen(ctx3)) != 0){
        goto fail;
    }

    if (asn1_get_value_dlen(ctx3) != 128 || zmcrypto_memcmp(asn1_get_value_data(ctx3), der_data + (129+3) + 3, asn1_get_value_dlen(ctx3)) != 0){
        goto fail;
    }

    goto succ;

fail:
    asn1_ctx_free(ctx);
    asn1_ctx_free(ctx2);
    asn1_ctx_free(ctx3);
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #4");
    return;

succ:

    asn1_ctx_free(ctx);
    asn1_ctx_free(ctx2);
    asn1_ctx_free(ctx3);
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #4");
    return;
}

void test_asn1_case5()
{
    if (std::string("SEQUENCE") != asn1_debug_tag_to_string(0x30)) { goto fail; }
    if (std::string("SET") != asn1_debug_tag_to_string(0x31)) { goto fail; }
    if (std::string("CONTEXT[0x00]") != asn1_debug_tag_to_string(0xa0)) { goto fail; }

    goto succ;

fail:

    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #5");
    return;

succ:

    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #5");
    return;
}

void test_asn1_case6()
{
/*
echo -e -n "\
\x30\x30\
\x30\x0e\x02\x05\x11\x11\x11\x11\x11\x02\x05\x22\x22\x22\x22\x22\
\x30\x0e\x02\x05\x33\x33\x33\x33\x33\x02\x05\x44\x44\x44\x44\x44\
\x30\x0e\x02\x05\x55\x55\x55\x55\x55\x02\x05\x66\x66\x66\x66\x66\
" > aaa.txt

#  0  48: SEQUENCE {
#  2  14:   SEQUENCE {
#  4   5:     INTEGER 11 11 11 11 11
# 11   5:     INTEGER 22 22 22 22 22
#       :     }
# 18  14:   SEQUENCE {
# 20   5:     INTEGER 33 33 33 33 33
# 27   5:     INTEGER 44 44 44 44 44
#       :     }
# 34  14:   SEQUENCE {
# 36   5:     INTEGER 55 55 55 55 55
# 43   5:     INTEGER 66 66 66 66 66
#       :     }
#       :   }

echo -e -n "\
\x30\x30\x30\x0e\x02\x05\x11\x11\x11\x11\x11\x02\x05\x22\x22\x22\
\x22\x22\x30\x0e\x02\x05\x33\x33\x33\x33\x33\x02\x05\x44\x44\x44\
\x44\x44\x30\x0e\x02\x05\x55\x55\x55\x55\x55\x02\x05\x66\x66\x66\
\x66\x66\
\x30\x30\x30\x0e\x02\x05\x1a\x1a\x1a\x1a\x1a\x02\x05\x2a\x2a\x2a\
\x2a\x2a\x30\x0e\x02\x05\x3a\x3a\x3a\x3a\x3a\x02\x05\x4a\x4a\x4a\
\x4a\x4a\x30\x0e\x02\x05\x5a\x5a\x5a\x5a\x5a\x02\x05\x6a\x6a\x6a\
\x6a\x6a\
\x30\x30\x30\x0e\x02\x05\x1d\x1d\x1d\x1d\x1d\x02\x05\x2d\x2d\x2d\
\x2d\x2d\x30\x0e\x02\x05\x3d\x3d\x3d\x3d\x3d\x02\x05\x4d\x4d\x4d\
\x4d\x4d\x30\x0e\x02\x05\x5d\x5d\x5d\x5d\x5d\x02\x05\x6d\x6d\x6d\
\x6d\x6d\
" > aaa.txt

  0  48: SEQUENCE {
  2  14:   SEQUENCE {
  4   5:     INTEGER 11 11 11 11 11
 11   5:     INTEGER 22 22 22 22 22
       :     }
 18  14:   SEQUENCE {
 20   5:     INTEGER 33 33 33 33 33
 27   5:     INTEGER 44 44 44 44 44
       :     }
 34  14:   SEQUENCE {
 36   5:     INTEGER 55 55 55 55 55
 43   5:     INTEGER 66 66 66 66 66
       :     }
       :   }
*/
    uint8_t nested_der[] = 
    {
        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66
    };
    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;
    uint32_t copy = 0;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;
    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<struct asn1_ctx*> _stack;
    std::vector<struct asn1_ctx*> _new;
    std::vector<struct asn1_ctx*> _free;

    std::vector<std::string> tags1;
    std::vector<std::string> tags2;
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER" );
    tags1.push_back("INTEGER" );
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER" );
    tags1.push_back("INTEGER" );
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER" );
    tags1.push_back("INTEGER" );

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);
        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }
        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        tags2.push_back(s);
        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);
            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    if (tags1 == tags2){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #6");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #6");
    return;
}

void test_asn1_case7()
{
/*
echo -e -n "\
\x30\x30\x30\x0e\x02\x05\x11\x11\x11\x11\x11\x02\x05\x22\x22\x22\
\x22\x22\x30\x0e\x02\x05\x33\x33\x33\x33\x33\x02\x05\x44\x44\x44\
\x44\x44\x30\x0e\x02\x05\x55\x55\x55\x55\x55\x02\x05\x66\x66\x66\
\x66\x66\
\x30\x30\x30\x0e\x02\x05\x1a\x1a\x1a\x1a\x1a\x02\x05\x2a\x2a\x2a\
\x2a\x2a\x30\x0e\x02\x05\x3a\x3a\x3a\x3a\x3a\x02\x05\x4a\x4a\x4a\
\x4a\x4a\x30\x0e\x02\x05\x5a\x5a\x5a\x5a\x5a\x02\x05\x6a\x6a\x6a\
\x6a\x6a\
\x30\x30\x30\x0e\x02\x05\x1d\x1d\x1d\x1d\x1d\x02\x05\x2d\x2d\x2d\
\x2d\x2d\x30\x0e\x02\x05\x3d\x3d\x3d\x3d\x3d\x02\x05\x4d\x4d\x4d\
\x4d\x4d\x30\x0e\x02\x05\x5d\x5d\x5d\x5d\x5d\x02\x05\x6d\x6d\x6d\
\x6d\x6d\
" > aaa.txt

  0  48: SEQUENCE {
  2  14:   SEQUENCE {
  4   5:     INTEGER 11 11 11 11 11
 11   5:     INTEGER 22 22 22 22 22
       :     }
 18  14:   SEQUENCE {
 20   5:     INTEGER 33 33 33 33 33
 27   5:     INTEGER 44 44 44 44 44
       :     }
 34  14:   SEQUENCE {
 36   5:     INTEGER 55 55 55 55 55
 43   5:     INTEGER 66 66 66 66 66
       :     }
       :   }

zhangluduo@zhangluduo-B85-HD3:~$ openssl asn1parse -in aaa.txt -inform DER
    0:d=0  hl=2 l=  48 cons: SEQUENCE          
         2:d=1  hl=2 l=  14 cons: SEQUENCE          
             4:d=2  hl=2 l=   5 prim: INTEGER           :1111111111
            11:d=2  hl=2 l=   5 prim: INTEGER           :2222222222
        18:d=1  hl=2 l=  14 cons: SEQUENCE          
            20:d=2  hl=2 l=   5 prim: INTEGER           :3333333333
            27:d=2  hl=2 l=   5 prim: INTEGER           :4444444444
        34:d=1  hl=2 l=  14 cons: SEQUENCE          
            36:d=2  hl=2 l=   5 prim: INTEGER           :5555555555
            43:d=2  hl=2 l=   5 prim: INTEGER           :6666666666
   50:d=0  hl=2 l=  48 cons: SEQUENCE          
        52:d=1  hl=2 l=  14 cons: SEQUENCE          
            54:d=2  hl=2 l=   5 prim: INTEGER           :1A1A1A1A1A
            61:d=2  hl=2 l=   5 prim: INTEGER           :2A2A2A2A2A
        68:d=1  hl=2 l=  14 cons: SEQUENCE          
            70:d=2  hl=2 l=   5 prim: INTEGER           :3A3A3A3A3A
            77:d=2  hl=2 l=   5 prim: INTEGER           :4A4A4A4A4A
        84:d=1  hl=2 l=  14 cons: SEQUENCE          
            86:d=2  hl=2 l=   5 prim: INTEGER           :5A5A5A5A5A
            93:d=2  hl=2 l=   5 prim: INTEGER           :6A6A6A6A6A
  100:d=0  hl=2 l=  48 cons: SEQUENCE          
        102:d=1  hl=2 l=  14 cons: SEQUENCE          
            104:d=2  hl=2 l=   5 prim: INTEGER           :1D1D1D1D1D
            111:d=2  hl=2 l=   5 prim: INTEGER           :2D2D2D2D2D
        118:d=1  hl=2 l=  14 cons: SEQUENCE          
            120:d=2  hl=2 l=   5 prim: INTEGER           :3D3D3D3D3D
            127:d=2  hl=2 l=   5 prim: INTEGER           :4D4D4D4D4D
        134:d=1  hl=2 l=  14 cons: SEQUENCE          
            136:d=2  hl=2 l=   5 prim: INTEGER           :5D5D5D5D5D
            143:d=2  hl=2 l=   5 prim: INTEGER           :6D6D6D6D6D
zhangluduo@zhangluduo-B85-HD3:~$ 
*/
    uint8_t nested_der[] = 
    {
        /*           0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f*/
        /* 000 */ 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        /* 001 */ 0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        /* 002 */ 0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        /* 003 */ 0x66, 0x66,

        /* 000 */ 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x02, 0x05, 0x2a, 0x2a, 0x2a,
        /* 001 */ 0x2a, 0x2a, 0x30, 0x0e, 0x02, 0x05, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x02, 0x05, 0x4a, 0x4a, 0x4a,
        /* 002 */ 0x4a, 0x4a, 0x30, 0x0e, 0x02, 0x05, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x02, 0x05, 0x6a, 0x6a, 0x6a,
        /* 003 */ 0x6a, 0x6a,

        /* 000 */ 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x02, 0x05, 0x2d, 0x2d, 0x2d,
        /* 001 */ 0x2d, 0x2d, 0x30, 0x0e, 0x02, 0x05, 0x3d, 0x3d, 0x3d, 0x3d, 0x3d, 0x02, 0x05, 0x4d, 0x4d, 0x4d,
        /* 002 */ 0x4d, 0x4d, 0x30, 0x0e, 0x02, 0x05, 0x5d, 0x5d, 0x5d, 0x5d, 0x5d, 0x02, 0x05, 0x6d, 0x6d, 0x6d,
        /* 003 */ 0x6d, 0x6d,
    };
    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;
    uint32_t copy = 0;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;
    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<struct asn1_ctx*> _stack;
    std::vector<struct asn1_ctx*> _new;
    std::vector<struct asn1_ctx*> _free;

    std::vector<std::string> tags1;
    std::vector<std::string> tags2;
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);
        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        /*printf ("%s\n", s);*/
        tags2.push_back(s);
        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);
            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx) ;
            dlen = asn1_get_next_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);

/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    if (tags1 == tags2){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #7");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #7");
    return;
}

void test_asn1_case8()
{
// echo -e -n "\
// \x30\x0f\
// \x30\x0a\
// \x31\x08\
// \x30\x06\x02\x01\x01\x02\x01\x02\
// \x02\x01\x03" > aaa.txt
//   0  15: SEQUENCE {
//   2  10:   SEQUENCE {
//   4   8:     SET {
//   6   6:       SEQUENCE {
//   8   1:         INTEGER 1
//  11   1:         INTEGER 2
//        :         }
//        :       }
//        :     }
//  14   1:   INTEGER 3
//        :   }

    uint8_t nested_der[] = 
    {
        0x30, 0x0f, 0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03
    };

    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;
    uint32_t copy = 0;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;
    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<struct asn1_ctx*> _stack;
    std::vector<struct asn1_ctx*> _new;
    std::vector<struct asn1_ctx*> _free;

    std::vector<std::string> tags1;
    std::vector<std::string> tags2;
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);
        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        /*printf ("%s\n", s);*/
        tags2.push_back(s);
        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);
            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);

/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    if (tags1 == tags2){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #8");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #8");
    return;
}

void test_asn1_case9()
{
    uint8_t* data = baidu_cert_der;
    uint32_t dlen = baidu_cert_der_len;
    uint32_t copy = 0;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;
    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<struct asn1_ctx*> _stack;
    std::vector<struct asn1_ctx*> _new;
    std::vector<struct asn1_ctx*> _free;

    std::vector<std::string> tags1;
    std::vector<std::string> tags2;
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("CONTEXT[0x00]");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("NULL");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("UTC_TIME");
    tags1.push_back("UTC_TIME");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("NULL");
    tags1.push_back("BIT_STRING");
    tags1.push_back("BIT_STRING");/* ! */
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("BOOLEAN");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("NULL");
    tags1.push_back("BIT_STRING");

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);
        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        /*printf ("%s\n", s);*/
        tags2.push_back(s);
        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);
            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);

/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    if (tags1 == tags2){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #9");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #9");
    return;
}

void test_asn1_case10()
{
    uint8_t* data = google_cert_der;
    uint32_t dlen = google_cert_der_len;
    uint32_t copy = 0;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;
    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<struct asn1_ctx*> _stack;
    std::vector<struct asn1_ctx*> _new;
    std::vector<struct asn1_ctx*> _free;

    std::vector<std::string> tags1;
    std::vector<std::string> tags2;
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("CONTEXT[0x00]");
    tags1.push_back("INTEGER");
    tags1.push_back("INTEGER");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("NULL");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("UTC_TIME");
    tags1.push_back("UTC_TIME");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SET");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("PRINTABLE_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("BIT_STRING");
    tags1.push_back("BIT_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("BOOLEAN");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("BOOLEAN");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("OCTET_STRING");
    tags1.push_back("SEQUENCE");
    tags1.push_back("OBJECT_IDENTIFIE");
    tags1.push_back("NULL");
    tags1.push_back("BIT_STRING");

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);
        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        /*printf ("%s\n", s);*/
        tags2.push_back(s);
        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);
            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);

/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    if (tags1 == tags2){
        goto succ;
    }
    else{
        goto fail;
    }

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #10");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #10");
    return;
}

void test_asn1_case11(){
/*
echo -e -n "\
\x30\x30\
\x30\x0e\x02\x05\x11\x11\x11\x11\x11\x02\x05\x22\x22\x22\x22\x22\
\x30\x0e\x02\x05\x33\x33\x33\x33\x33\x02\x05\x44\x44\x44\x44\x44\
\x30\x0e\x02\x05\x55\x55\x55\x55\x55\x02\x05\x66\x66\x66\x66\x66\
" > aaa.txt

#  0  48: SEQUENCE {
#  2  14:   SEQUENCE {
#  4   5:     INTEGER 11 11 11 11 11
# 11   5:     INTEGER 22 22 22 22 22
#       :     }
# 18  14:   SEQUENCE {
# 20   5:     INTEGER 33 33 33 33 33
# 27   5:     INTEGER 44 44 44 44 44
#       :     }
# 34  14:   SEQUENCE {
# 36   5:     INTEGER 55 55 55 55 55
# 43   5:     INTEGER 66 66 66 66 66
#       :     }
#       :   }
*/
    uint8_t nested_der[] = 
    {
        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66
    };

    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;

    uint32_t copy = 1;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;

    struct asn1_ctx* ctx = NULL;
    asn1_ctx* top = NULL;
    std::stack<asn1_ctx*> _stack;
    std::vector<asn1_ctx*> _new;
    std::vector<asn1_ctx*> _free;

    struct asn1_ctx_item{
        std::string tag_name;
        uint32_t level;
        uint32_t offset;
    };
    std::vector<asn1_ctx_item> item_list1;
    std::vector<asn1_ctx_item> item_list2;

    { asn1_ctx_item item1 = {"SEQUENCE", 0,  0}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  2}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  4}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 11}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1, 18}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 20}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 27}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1, 34}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 36}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 43}; item_list1.push_back(item1); }

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);

        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        { asn1_ctx_item item1 = {s, level, offset}; item_list2.push_back(item1); }

        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* tag is constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);

            level++;
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx);

            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;
                level--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    for (int i = 0; i < item_list1.size() && item_list1.size() == item_list2.size(); i++){
        if (item_list1[i].tag_name != item_list2[i].tag_name ||
            item_list1[i].level != item_list2[i].level ||
            item_list1[i].offset != item_list2[i].offset){
                printf ("item error : %d, %s %d %d\n", i, item_list2[i].tag_name.c_str(), item_list2[i].level, item_list2[i].offset);
                goto fail;
            }
    }

    goto succ;

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #11");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #11");
    return;
}

void test_asn1_case12(){
    uint8_t nested_der[] = 
    {
        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66,

        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66,

        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66
    };

    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;

    uint32_t copy = 1;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;

    struct asn1_ctx* ctx = NULL;
    asn1_ctx* top = NULL;
    std::stack<asn1_ctx*> _stack;
    std::vector<asn1_ctx*> _new;
    std::vector<asn1_ctx*> _free;

    struct asn1_ctx_item{
        std::string tag_name;
        uint32_t level;
        uint32_t offset;
    };
    std::vector<asn1_ctx_item> item_list1;
    std::vector<asn1_ctx_item> item_list2;

// zhangluduo@zhangluduo-B85-HD3:~$ openssl asn1parse -in aaa.txt -inform DER
//     0:d=0  hl=2 l=  48 cons: SEQUENCE          
//          2:d=1  hl=2 l=  14 cons: SEQUENCE          
//              4:d=2  hl=2 l=   5 prim: INTEGER           :1111111111
//             11:d=2  hl=2 l=   5 prim: INTEGER           :2222222222
//         18:d=1  hl=2 l=  14 cons: SEQUENCE          
//             20:d=2  hl=2 l=   5 prim: INTEGER           :3333333333
//             27:d=2  hl=2 l=   5 prim: INTEGER           :4444444444
//         34:d=1  hl=2 l=  14 cons: SEQUENCE          
//             36:d=2  hl=2 l=   5 prim: INTEGER           :5555555555
//             43:d=2  hl=2 l=   5 prim: INTEGER           :6666666666
//    50:d=0  hl=2 l=  48 cons: SEQUENCE          
//         52:d=1  hl=2 l=  14 cons: SEQUENCE          
//             54:d=2  hl=2 l=   5 prim: INTEGER           :1A1A1A1A1A
//             61:d=2  hl=2 l=   5 prim: INTEGER           :2A2A2A2A2A
//         68:d=1  hl=2 l=  14 cons: SEQUENCE          
//             70:d=2  hl=2 l=   5 prim: INTEGER           :3A3A3A3A3A
//             77:d=2  hl=2 l=   5 prim: INTEGER           :4A4A4A4A4A
//         84:d=1  hl=2 l=  14 cons: SEQUENCE          
//             86:d=2  hl=2 l=   5 prim: INTEGER           :5A5A5A5A5A
//             93:d=2  hl=2 l=   5 prim: INTEGER           :6A6A6A6A6A
//   100:d=0  hl=2 l=  48 cons: SEQUENCE          
//         102:d=1  hl=2 l=  14 cons: SEQUENCE          
//             104:d=2  hl=2 l=   5 prim: INTEGER           :1D1D1D1D1D
//             111:d=2  hl=2 l=   5 prim: INTEGER           :2D2D2D2D2D
//         118:d=1  hl=2 l=  14 cons: SEQUENCE          
//             120:d=2  hl=2 l=   5 prim: INTEGER           :3D3D3D3D3D
//             127:d=2  hl=2 l=   5 prim: INTEGER           :4D4D4D4D4D
//         134:d=1  hl=2 l=  14 cons: SEQUENCE          
//             136:d=2  hl=2 l=   5 prim: INTEGER           :5D5D5D5D5D
//             143:d=2  hl=2 l=   5 prim: INTEGER           :6D6D6D6D6D
// zhangluduo@zhangluduo-B85-HD3:~$ 

    { asn1_ctx_item item1 = {"SEQUENCE", 0,   0}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,   2}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,   4}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  11}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  18}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  20}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  27}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  34}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  36}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  43}; item_list1.push_back(item1); }

    { asn1_ctx_item item1 = {"SEQUENCE", 0,  50}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  52}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  54}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  61}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  68}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  70}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  77}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,  84}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  86}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,  93}; item_list1.push_back(item1); }
    
    { asn1_ctx_item item1 = {"SEQUENCE", 0, 100}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1, 102}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 104}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 111}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1, 118}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 120}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 127}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1, 134}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 136}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2, 143}; item_list1.push_back(item1); }

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);

        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        { asn1_ctx_item item1 = {s, level, offset}; item_list2.push_back(item1); }

        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* tag is constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);

            level++;
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx);

            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;
                level--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    for (int i = 0; i < item_list1.size() && item_list1.size() == item_list2.size(); i++){
        if (item_list1[i].tag_name != item_list2[i].tag_name ||
            item_list1[i].level != item_list2[i].level ||
            item_list1[i].offset != item_list2[i].offset){
                printf ("item error : %d, %s %d %d\n", i, item_list2[i].tag_name.c_str(), item_list2[i].level, item_list2[i].offset);
                goto fail;
            }
    }

    goto succ;

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #12");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #12");
    return;
}

void test_asn1_case13(){
    uint8_t nested_der[] = 
    {
        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66,

        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66,

        0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        0x66, 0x66
    };

    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = nested_der;
    uint32_t dlen = nested_der_len;

    uint32_t copy = 1;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;

    struct asn1_ctx* ctx = NULL;
    asn1_ctx* top = NULL;
    std::stack<asn1_ctx*> _stack;
    std::vector<asn1_ctx*> _new;
    std::vector<asn1_ctx*> _free;

    struct asn1_ctx_item{
        std::string tag_name;
        uint32_t level;
        uint32_t offset;
    };
    std::vector<asn1_ctx_item> item_list1;
    std::vector<asn1_ctx_item> item_list2;

// echo -e -n "\
// \x30\x0f\
// \x30\x0a\
// \x31\x08\
// \x30\x06\x02\x01\x01\x02\x01\x02\
// \x02\x01\x03" > aaa.txt
//   0  15: SEQUENCE {
//   2  10:   SEQUENCE {
//   4   8:     SET {
//   6   6:       SEQUENCE {
//   8   1:         INTEGER 1
//  11   1:         INTEGER 2
//        :         }
//        :       }
//        :     }
//  14   1:   INTEGER 3
//        :   }

    { asn1_ctx_item item1 = {"SEQUENCE", 0,   0}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 1,   2}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  2,   4}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  3,   6}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE", 4,   8}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  4,  11}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER",  1,  14}; item_list1.push_back(item1); }

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);

        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        { asn1_ctx_item item1 = {s, level, offset}; item_list2.push_back(item1); }

        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* tag is constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);

            level++;
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx);

            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;
                level--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    for (int i = 0; i < item_list1.size() && item_list1.size() == item_list2.size(); i++){
        if (item_list1[i].tag_name != item_list2[i].tag_name ||
            item_list1[i].level != item_list2[i].level ||
            item_list1[i].offset != item_list2[i].offset){
                printf ("item error : %d, %s %d %d\n", i, item_list2[i].tag_name.c_str(), item_list2[i].level, item_list2[i].offset);
                goto fail;
            }
    }

    goto succ;

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #13");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #13");
    return;
}

void test_asn1_case14(){

    uint8_t* data = baidu_cert_der;
    uint32_t dlen = baidu_cert_der_len;

    uint32_t copy = 1;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;

    struct asn1_ctx* ctx = NULL;
    asn1_ctx* top = NULL;
    std::stack<asn1_ctx*> _stack;
    std::vector<asn1_ctx*> _new;
    std::vector<asn1_ctx*> _free;

    struct asn1_ctx_item{
        std::string tag_name;
        uint32_t level;
        uint32_t offset;
    };
    std::vector<asn1_ctx_item> item_list1;
    std::vector<asn1_ctx_item> item_list2;

    { asn1_ctx_item item1 = {"SEQUENCE"                ,    0,   0}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    1,   4}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"CONTEXT[0x00]"           ,    2,   8}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER"                 ,    3,  10}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"INTEGER"                 ,    2,  13}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    2,  27}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    3,  29}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"NULL"                    ,    3,  40}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    2,  42}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3,  44}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,  46}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,  48}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5,  53}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3,  57}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,  59}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,  61}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5,  66}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3,  84}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,  86}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,  88}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5,  93}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    2, 124}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"UTC_TIME"                ,    3, 126}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"UTC_TIME"                ,    3, 141}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    2, 156}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3, 159}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 161}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 163}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5, 168}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3, 172}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 174}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 176}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5, 181}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3, 190}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 192}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 194}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5, 199}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3, 208}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 210}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 212}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5, 217}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SET"                     ,    3, 267}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 269}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 271}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"PRINTABLE_STRING"        ,    5, 276}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    2, 287}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    3, 291}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    4, 293}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"NULL"                    ,    4, 304}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"BIT_STRING"              ,    3, 306}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"BIT_STRING"              ,    2, 581}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    3, 585}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 589}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 591}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"BOOLEAN"                 ,    5, 596}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 599}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 605}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 608}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 618}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 750}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 752}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 757}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 838}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 840}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 845}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 849}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 851}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 856}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4, 914}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5, 918}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5, 923}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,1783}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,1785}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5,1790}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,1814}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,1816}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5,1821}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,1847}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,1849}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5,1854}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    4,1878}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    5,1882}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OCTET_STRING"            ,    5,1894}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"SEQUENCE"                ,    1,2264}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"OBJECT_IDENTIFIE"        ,    2,2266}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"NULL"                    ,    2,2277}; item_list1.push_back(item1); }
    { asn1_ctx_item item1 = {"BIT_STRING"              ,    1,2279}; item_list1.push_back(item1); }

_begin:
    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);

        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        const char* s = asn1_debug_tag_to_string(asn1_get_tag_data(ctx)[0]);
        { asn1_ctx_item item1 = {s, level, offset}; item_list2.push_back(item1); }

        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* tag is constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);

            level++;
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx);

            _stack.push(ctx);
            pushed++;
            continue;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
            continue;
        }
        else{
_pop:
            top = _stack.top();
            if (top){
                _stack.pop();
                pushed--;
                level--;

                if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                    data = asn1_get_next_data(top);
                    dlen = asn1_get_next_dlen(top);
                    offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
                    goto _begin;
                }
                else if (pushed > 0){
                    goto _pop;
                }
                break;
            }
            break;
        }

    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    for (int i = 0; i < item_list1.size() && item_list1.size() == item_list2.size(); i++){
        if (item_list1[i].tag_name != item_list2[i].tag_name ||
            item_list1[i].level != item_list2[i].level ||
            item_list1[i].offset != item_list2[i].offset){
                printf ("item error : %d, %s %d %d\n", i, item_list2[i].tag_name.c_str(), item_list2[i].level, item_list2[i].offset);
                goto fail;
            }
    }

    goto succ;

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #14");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #14");
    return;
}

void test_asn1_case15(){
    uint8_t nested_der[] = 
    {
        // 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        // 0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        // 0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        // 0x66, 0x66,

        // 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        // 0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        // 0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        // 0x66, 0x66,

        // 0x30, 0x30, 0x30, 0x0e, 0x02, 0x05, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x05, 0x22, 0x22, 0x22,
        // 0x22, 0x22, 0x30, 0x0e, 0x02, 0x05, 0x33, 0x33, 0x33, 0x33, 0x33, 0x02, 0x05, 0x44, 0x44, 0x44,
        // 0x44, 0x44, 0x30, 0x0e, 0x02, 0x05, 0x55, 0x55, 0x55, 0x55, 0x55, 0x02, 0x05, 0x66, 0x66, 0x66,
        // 0x66, 0x66

        0x30, 0x0f, 0x30, 0x0a, 0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03
    };

    uint32_t nested_der_len = sizeof(nested_der);

    uint8_t* data = baidu_cert_der;
    uint32_t dlen = baidu_cert_der_len;

    // uint8_t* data = nested_der;
    // uint32_t dlen = nested_der_len;

    uint32_t copy = 1;
    uint32_t result = 0;
    uint32_t level = 0;
    uint32_t offset = 0;
    uint32_t pushed = 0;

    struct asn1_ctx* ctx = NULL;
    struct asn1_ctx* top = NULL;
    std::stack<asn1_ctx*> _stack;
    std::vector<asn1_ctx*> _new;
    std::vector<asn1_ctx*> _free;

    do
    {
        ctx = asn1_ctx_new(); 
        _new.push_back(ctx);
        _free.push_back(ctx);

        zmerror err = asn1_parse_data(data, dlen, ctx, copy);
        if (ZMCRYPTO_IS_ERROR(err)){
            goto fail;
        }

        helper_print_asn1_ctx(ctx, level, offset);

        (void)asn1_is_tag_constructed(asn1_get_tag_data(ctx)[0], &result);

        /* tag is constructed */
        if (result == 1){
            data = asn1_get_value_data(ctx);
            dlen = asn1_get_value_dlen(ctx);

            level++;
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx);

            _stack.push(ctx);
            pushed++;
        }
        /* has next */
        else if(asn1_get_next_data(ctx) != NULL && asn1_get_next_dlen(ctx) > 0){
            data = asn1_get_next_data(ctx);
            dlen = asn1_get_next_dlen(ctx);
            offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);
        }
        else{
            int exit_parent_while = 0;
            do{
                top = _stack.top();
                if (top){
                    _stack.pop();
                    pushed--;
                    level--;

                    if(asn1_get_next_data(top) != NULL && asn1_get_next_dlen(top) > 0){
                        data = asn1_get_next_data(top);
                        dlen = asn1_get_next_dlen(top);
                        offset += asn1_get_tag_dlen(ctx) + asn1_get_length_dlen(ctx) + asn1_get_value_dlen(ctx);

                        helper_print_asn1_right_end(level, offset);
                        break;
                    }
                    else if (pushed > 0){
                        helper_print_asn1_right_end(level, offset);
                        continue;
                    }
                    else{
                        helper_print_asn1_right_end(level, offset);
                        exit_parent_while = 1;
                        break;
                    }
                }
                else{
                    helper_print_asn1_right_end(level, offset);
                    exit_parent_while = 1;
                    break;
                }
            }while (top != NULL);

            if (exit_parent_while == 1){
                break;
            }
        } /*end else*/
    } while (/*ctx != NULL*/true);
/*
    printf("new(%d): \n", _new.size());
    for (int i = 0; i < _new.size(); i++){
        printf ("%p\n", _new[i]);
    }   printf("\n");

    printf("free(%d): \n", _free.size());
    for (int i = 0; i < _free.size(); i++){
        printf ("%p\n", _free[i]);
        asn1_ctx_free(_free[i]); 
    }   printf("\n");
*/

    for (int i = 0; i < _free.size(); i++){
        asn1_ctx_free(_free[i]); 
    }

    goto succ;

fail:
    format_output("%s by ZmCrypto|%s failed\n", "asn1", "case #15");
    return;

succ:
    format_output("%s by ZmCrypto|%s passed\n", "asn1", "case #15");
    return;
}