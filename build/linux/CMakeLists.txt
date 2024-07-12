

cmake_minimum_required(VERSION 3.0)
project(zmcrypto)

#set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE Release)

#add_definitions(-w -W)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
	message("Build Type: Debug")
    add_definitions(
        -DDEBUG
    )
else()
	message("Build Type: Release")
endif()

#set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -g2 -ggdb -std=c++11")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall ")
#set(CMAKE_CXX_FLAGS "-fvisibility=hidden")

#------------------- zmcrypto.so -------------------
add_library(
	zmcrypto
	SHARED
	../../src/adler32.c
	../../src/blockpad.c
	../../src/base64.c
	../../src/base58.c
	../../src/base32.c
	../../src/base16.c
	../../src/crc32.c
	../../src/md5.c
	../../src/md4.c
	../../src/md2.c
	../../src/ed2k.c
	../../src/sha1.c
	../../src/sha2.c
	../../src/sha3.c
	../../src/sm3.c
	../../src/aes.c
	../../src/des.c
	../../src/blowfish.c
	../../src/twofish.c
	../../src/sm4.c
	../../src/tea.c
	../../src/xtea.c
	../../src/ecb.c
	../../src/cbc.c
	../../src/cfb.c
	../../src/ofb.c
	../../src/ctr.c
	../../src/hmac.c
	../../src/cmac.c
	../../src/ccm.c
	../../src/gcm.c
	../../src/pbkdf2.c
	../../src/rc4.c
	../../src/salsa20.c
	../../src/asn1.c
	../../src/mem.c
	../../src/zmcrypto.c
)

set_target_properties(
    zmcrypto 
    PROPERTIES PREFIX "" SUFFIX ".so"
)

#------------------- hook.so -------------------
add_library(
	hook
	SHARED
	../../hook/replace_aes.c
	../../hook/hook.c
)

set_target_properties(
    hook 
    PROPERTIES PREFIX "" SUFFIX ".so"
)

target_link_libraries (hook LINK_PUBLIC 
	dl
	pthread
)

#------------------- test -------------------

include_directories(
	${PROJECT_SOURCE_DIR}/../../tests/cpp/ # for zmcrypto.h
	${PROJECT_SOURCE_DIR}/../../src/ # for zmcryptosdk.h
	/home/zhangluduo/data2t/toolchain/cryptopp820/
	/home/zhangluduo/data2t/toolchain/mbedtls-3.0.0/include
)

link_directories(

	/home/zhangluduo/data2t/toolchain/cryptopp820/lib/linux_x64
	/home/zhangluduo/data2t/toolchain/mbedtls-3.0.0/library
)

add_definitions(
	-DTEST_FOR_CRYPTOPP
	-DTEST_FOR_CRYPTOPP_SPEED
	-DTEST_FOR_OPENSSL_SPEED
	-DTEST_FOR_MBEDTLS_SPEED
	-DDONOT_DETECT_MEM_LEAK_FOR_CRYPTOPP
)

add_executable(
	test
	../../src/zmconfig.h
	../../src/zmcrypto.h

	../../tests/cpp/main.cpp
	../../tests/cpp/zmcryptosdk.cpp
	../../tests/cpp/vector_file.cpp	
	../../tests/cpp/format_output.cpp
	../../tests/cpp/machine_info.cpp
	../../tests/cpp/time_stamp.cpp

	../../tests/cpp/test_adler32.cpp
	../../tests/cpp/test_crc32.cpp
	../../tests/cpp/test_base16.cpp
	../../tests/cpp/test_base64.cpp
	../../tests/cpp/test_md2.cpp
	../../tests/cpp/test_md4.cpp
	../../tests/cpp/test_md5.cpp
	../../tests/cpp/test_ed2k.cpp
	../../tests/cpp/test_sha1.cpp
	../../tests/cpp/test_sha2.cpp
	../../tests/cpp/test_sha3.cpp
	../../tests/cpp/test_sm3.cpp
	../../tests/cpp/test_hmac.cpp
	../../tests/cpp/test_cmac.cpp
	../../tests/cpp/test_ccm.cpp
	../../tests/cpp/test_gcm.cpp
	../../tests/cpp/test_pbkdf2.cpp
	../../tests/cpp/test_aes.cpp
	../../tests/cpp/test_des.cpp
	../../tests/cpp/test_rc4.cpp
	../../tests/cpp/test_sm4.cpp
	../../tests/cpp/test_xtea.cpp
	../../tests/cpp/test_blowfish.cpp
	../../tests/cpp/test_blockpad.cpp
	../../tests/cpp/test_hook.cpp
	../../tests/cpp/test_asn1.cpp
	../../src/asn1.c
)

target_link_libraries (test LINK_PUBLIC 
	dl
	cryptopp #Crypto++ Library
	crypto #libcrypto for openssl 
	mbedcrypto #libmbedcrypto.a
	pthread
)

#------------------- APPs -------------------
#
#add_executable(
#	app_asn1
#	../../app/app_asn1.c
#)
#
#add_executable(
#	app_x509
#	../../app/app_x509.c
#)
#
#add_executable(
#	app_bitoper
#	../../app/app_bitoper.c
#)
#
#add_executable(
#	app_hex
#	../../app/app_hex.c
#)
