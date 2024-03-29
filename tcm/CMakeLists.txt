cmake_minimum_required(VERSION 3.9)
project(libtcm LANGUAGES C CXX)

set(SOURCES
  src/tcm_log.c
  src/tcm_socket.c
  src/tcm_errno.cpp
  src/tcm_beacon.cpp
  src/tcm_fabric.cpp
  src/tcm_fabric_cq.cpp
  src/tcm_fabric_peer.cpp
  src/tcm_fabric_init.cpp
  src/tcm_fabric_shared.cpp
  src/tcm_endpoint.cpp
  src/tcm_conn.cpp
  src/tcm_comm.cpp
  src/tcm_mem.cpp
  src/tcm_msg.cpp
  src/tcm_mm.cpp
  src/tcm_time.cpp
  src/tcm_version.cpp
)

find_library(Libfabric NAMES fabric)

add_compile_options(
  "-Wall"
  "-Wextra"
  "$<$<CONFIG:DEBUG>:-O0;-g3;-ggdb>"
)

add_library(tcm STATIC ${SOURCES})
set_property(TARGET tcm PROPERTY C_STANDARD 99)
set_property(TARGET tcm PROPERTY CXX_STANDARD 11)

target_link_libraries(tcm fabric)
target_include_directories(tcm
	PUBLIC
		include
	PRIVATE
		src
)

