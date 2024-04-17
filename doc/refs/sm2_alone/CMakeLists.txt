
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

project ("engine_demo") 


set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

include_directories(
  #${CMAKE_CURRENT_BINARY_DIR}/../mallory/jsoncpp/include/
  #/home/zhangluduo/work/opensource2/cryptopp_820_static/include
  #/home/zhangluduo/work/project_03_phytium_ref/openssl-1.1.1m/include
  #${CMAKE_CURRENT_BINARY_DIR}/cryptopp820/include
)

link_directories(
    #/home/zhangluduo/work/project_03_phytium_ref/openssl-1.1.1m/
    #${CMAKE_CURRENT_BINARY_DIR}/cryptopp820/lib/linux_x64
)

file(GLOB sources 
    "*.h" "*.cpp" "*.c"
)

#list(REMOVE_ITEM sources "test_for_engine.cpp")

#set (SRC
#    test_for_engine.cpp
#    log.cpp
#)

#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

ADD_DEFINITIONS(
    -w -W -Wformat
    -D_CRYPTOPP
    -D_DONT_DETECT_LEAK_FOR_CRYPTOPP
)

#set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g -g2 -ggdb -std=c++11 ")
#set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall ")

#if (CMAKE_BUILD_TYPE STREQUAL Debug)
#endif()

#add_definitions(
#    -DCOMPILE_AS_SL
#)

#set(CMAKE_CXX_FLAGS "-fvisibility=hidden")

#add_library(test SHARED ${sources})

#add_executable(
#    MyEngine ${sources}
#)



#add_library(engine_demo
#    SHARED ${sources}
#)

#set_target_properties(
#    engine_demo 
#    PROPERTIES PREFIX "" SUFFIX ".so"
#)

#target_link_libraries(
#    engine_demo
#    dl
#    crypto #libcrypto.a
#    ssl #libssl.a
#)

#target_link_options(
#    engine_demo PRIVATE 
#    -pthread
#    #-fPIC
#)

add_executable(test ${sources})
target_link_libraries(test 
dl
crypto #libcrypto.a
#ssl #libssl.a
#cryptopp
#gmssl
)

