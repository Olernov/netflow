project(nf-parser)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++11 -Wall")

cmake_minimum_required(VERSION 2.8)
include_directories(PROJECT_SOURCE_DIR)
include_directories(/usr/lib/oracle/12.1/client64/include)
include_directories(/usr/include/boost)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

