CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(WBSM4)

include_directories(include)

aux_source_directory(src WB_SRC)

add_library(WB_LIB ${WB_SRC})

add_executable(WBSM4 test/main.c)

target_link_libraries(WBSM4 WB_LIB)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2")