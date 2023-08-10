

cmake_minimum_required(VERSION 3.0)
project(engine)

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

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -g2 -ggdb -std=c++11")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall ")
set(CMAKE_CXX_FLAGS "-fvisibility=hidden")

add_library(
	engine
	SHARED
	aes.c
	md5.c
)

add_definitions(
	#-DTEST_FOR_CRYPTOPP
	#-DNOT_DETECT_MEM_LEAK_FOR_CRYPTOPP
)
