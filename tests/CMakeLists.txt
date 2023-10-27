cmake_minimum_required(VERSION 3.9)
project(tcm_test LANGUAGES C CXX)

set(CLIENT_SOURCES
    client.cpp
)

set(SERVER_SOURCES
    server.cpp
)

add_subdirectory(../tcm tcm_bin/)

add_executable(server ${SERVER_SOURCES})
add_executable(client ${CLIENT_SOURCES})

target_link_libraries(server tcm)
target_link_libraries(client tcm)

add_compile_options(
  "-Wall"
  "-Wextra"
  "-Werror"
  "-O0"
  "-g"
)