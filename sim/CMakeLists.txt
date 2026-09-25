cmake_minimum_required(VERSION 3.20)
project(airframe_sim VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)

option(AIRFRAME_SANITIZE "Build with ASan+UBSan" OFF)
if(AIRFRAME_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------- library
add_library(airframe_core
  src/types.cpp
  src/rng.cpp
  src/json.cpp
  src/logger.cpp
  src/pcap_writer.cpp
  src/frame.cpp
  src/faults.cpp
  src/state_machine.cpp
)
target_include_directories(airframe_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---------------------------------------------------------------- binary
add_executable(airframe-sim src/main.cpp src/server.cpp)
target_link_libraries(airframe-sim PRIVATE airframe_core)
set_target_properties(airframe-sim PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ---------------------------------------------------------------- tests
include(CTest)
option(AIRFRAME_BUILD_TESTS "Build the GoogleTest suite" ON)

if(AIRFRAME_BUILD_TESTS AND BUILD_TESTING)
  include(FetchContent)
  # Pinned to a release tag, not a branch: an unpinned dependency makes a
  # "deterministic" build depend on whatever upstream did this morning.
  FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
    GIT_SHALLOW    TRUE
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(airframe_tests
    tests/test_state_machine.cpp
    tests/test_faults.cpp
    tests/test_determinism.cpp
    tests/test_pcap.cpp
    tests/test_frame.cpp
    tests/test_json.cpp
  )
  target_link_libraries(airframe_tests PRIVATE airframe_core GTest::gtest_main)
  # gtest itself is not warning-clean under -Wconversion; don't fail on its headers.
  target_compile_options(airframe_tests PRIVATE -Wno-conversion -Wno-sign-conversion)

  include(GoogleTest)
  gtest_discover_tests(airframe_tests PROPERTIES TIMEOUT 60)
endif()
