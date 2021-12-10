cmake_minimum_required(VERSION 3.13.1)

project(mini_aes VERSION 1.0)

# need to define the target first
add_executable(mini_aes 
    "${CMAKE_SOURCE_DIR}/src/mini_aes.c")

configure_file(Config.h.in Config.h)
target_include_directories(mini_aes PUBLIC 
    "${CMAKE_BINARY_DIR}"
    "${CMAKE_SOURCE_DIR}/include")