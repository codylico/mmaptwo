
cmake_minimum_required(VERSION 3.0)

project(mmaptwo C)

option(BUILD_TESTING "Enable testing.")
option(BUILD_SHARED_LIBS "Enable shared library construction.")
set(MMAPTWO_OS CACHE STRING "Target memory mapping API.")

add_library(mmaptwo "mmaptwo.c" "mmaptwo.h")
if (MMAPTWO_OS GREATER -1)
  target_compile_definitions(mmaptwo
    PRIVATE "MMAPTWO_OS=${MMAPTWO_OS}")
endif (MMAPTWO_OS GREATER -1)

if (BUILD_TESTING)
  add_executable(mmaptwo_dump "tests/dump.c")
  target_link_libraries(mmaptwo_dump mmaptwo)

  add_executable(mmaptwo_config "tests/config.c")
  target_link_libraries(mmaptwo_config mmaptwo)
endif (BUILD_TESTING)

