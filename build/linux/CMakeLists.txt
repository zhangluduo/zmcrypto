

cmake_minimum_required(VERSION 3.0)
project(zmcrypto)

set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

add_definitions(-w -W)

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

add_library(
	zmcrypto
	SHARED
	../../src/adler32.c
	../../src/blockpad.c
	../../src/base64.c
	../../src/base58.c
	../../src/base32.c
	../../src/crc32.c
	../../src/md5.c
	../../src/sha1.c
	../../src/sha2.c
	../../src/sha3.c
	../../src/aes.c
	../../src/des.c
	../../src/blowfish.c
	../../src/twofish.c
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
	../../src/mem.c
	../../src/dlmain.c
	../../src/debug.c
	../../src/zmcrypto.c
)

include_directories(
	${PROJECT_SOURCE_DIR}/../../tests/cpp/ # for zmcrypto.h
	${PROJECT_SOURCE_DIR}/../../src/ # for zmcryptosdk.h
)

link_directories(
	${PROJECT_SOURCE_DIR}/../../tests/cpp/cryptopp820/lib/linux_x64
)

add_definitions(
	#-DTEST_FOR_CRYPTOPP
	#-DDONOT_DETECT_MEM_LEAK_FOR_CRYPTOPP
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
	../../tests/cpp/test_base64.cpp
	../../tests/cpp/test_md5.cpp
	../../tests/cpp/test_sha1.cpp
	../../tests/cpp/test_hmac.cpp
	../../tests/cpp/test_cmac.cpp
	../../tests/cpp/test_ccm.cpp
	../../tests/cpp/test_pbkdf2.cpp
	../../tests/cpp/test_aes.cpp
	../../tests/cpp/test_des.cpp
	../../tests/cpp/test_rc4.cpp
	../../tests/cpp/test_blowfish.cpp
	../../tests/cpp/test_blockpad.cpp
	../../tests/cpp/test_engine.cpp
)

target_link_libraries (test LINK_PUBLIC 
	dl
	#cryptopp #Crypto++ Library
)
