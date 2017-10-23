project(nf-aggregator)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++14 -Wall")

cmake_minimum_required(VERSION 2.8)
include_directories(PROJECT_SOURCE_DIR)
include_directories(~/projects/Common)
include_directories(/usr/include/oracle/11.2/client64)
include_directories(/usr/include/boost)

aux_source_directory(. SRC_LIST)
aux_source_directory(/home/oleg/projects/Common SRC_LIST)

link_directories(/usr/lib/oracle/11.2/client64/lib)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries (${PROJECT_NAME} libboost_system.so)
target_link_libraries (${PROJECT_NAME} libboost_filesystem.so)
target_link_libraries (${PROJECT_NAME} libboost_thread.so)
target_link_libraries (${PROJECT_NAME} libclntsh.so)
