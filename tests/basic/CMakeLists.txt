cmake_minimum_required(VERSION 3.9)
project(tcm_test_basic LANGUAGES C CXX)

get_filename_component(PROJECT_TOP
 "${CMAKE_CURRENT_SOURCE_DIR}/../.."
 ABSOLUTE
)

get_filename_component(TCM_TOP
 "${PROJECT_TOP}/tcm"
 ABSOLUTE
)

add_subdirectory("${TCM_TOP}" tcm_bin/)

add_compile_options(
  "-Wall"
  "-Wextra"
  "-Werror"
  "-O0"
  "-g"
)

set(CLIENT_SOURCES
    client.cpp
)

set(SERVER_SOURCES
    server.cpp
)


add_executable(server ${SERVER_SOURCES})
add_executable(client ${CLIENT_SOURCES})

target_link_libraries(server tcm)
target_link_libraries(client tcm)

