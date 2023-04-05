cmake_minimum_required(VERSION 3.0.0)
project(libtcm LANGUAGES C)

set(SOURCES
  src/tcm.c
  src/tcm_log.c
  src/tcm_msg.c
  src/tcm_udp.c
  src/tcm_fabric.c
  src/tcmu.c
)

find_library(Libfabric NAMES fabric)

add_compile_options(
  "-Wall"
  "-Werror"
  "-Wfatal-errors"
  "-fdata-sections"
  "-ffunction-sections"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

add_library(tcm STATIC ${SOURCES})
set_property(TARGET tcm PROPERTY C_STANDARD 99)

target_link_libraries(tcm fabric)
target_include_directories(tcm
	PUBLIC
		include
	PRIVATE
		src
)

