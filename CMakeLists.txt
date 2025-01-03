cmake_minimum_required(VERSION 3.16)

project("pingu")

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "-std=c++20 ${CMAKE_CXX_FLAGS} -Wall -Wpedantic -O3 -g -march=native -mtune=native -fsanitize=undefined")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(${CMAKE_PROJECT_NAME} src/main.cpp src/x86_64.cpp src/elf.cpp src/tac.cpp)