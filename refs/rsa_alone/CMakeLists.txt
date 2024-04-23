CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
 
PROJECT(test)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

#include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../cryptopp_820/include)
#link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../cryptopp_820/lib/linux_x64)

file(GLOB sources 
    "*.h" "*.cpp" 
)

#set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE Release)

#set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -g2 -ggdb -std=c++11 -Wunused-variable")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
#set(CMAKE_CXX_FLAGS "-fvisibility=hidden")

#if (CMAKE_BUILD_TYPE STREQUAL Debug)
#    add_definitions(
#        -D_DEBUG
#    )
#endif()

#ADD_DEFINITIONS(
#    -D_CRYPTOPP
#    -D_DONT_DETECT_LEAK_FOR_CRYPTOPP
#)

add_definitions(-w)
add_executable(test ${sources})
target_link_libraries(test dl 
crypto)
#target_link_libraries(test dl)

