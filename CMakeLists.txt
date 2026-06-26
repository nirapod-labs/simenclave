cmake_minimum_required(VERSION 3.24)
project(SimEnclave LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# The interposer runs in two kinds of slice. ON builds a simulator slice (the
# injectable dylib and the in-simulator demo); OFF builds the macOS host slice
# (the integration harness and the C unit tests). The Makefile configures one
# build tree per slice and sets its SDK and target triple, which is the idiomatic
# way to cross-compile with CMake.
option(SIMENCLAVE_SIM_SLICE "Build a simulator slice" OFF)

# Which simulator platform the slice targets. The Makefile passes the matching SDK
# and -target; this only names the output, so each platform's dylib gets a distinct
# file (an ios-simulator and a watchos-simulator slice are both arm64 and cannot
# share one fat binary). The ios default keeps the canonical simenclave-interpose.
set(SIMENCLAVE_SIM_PLATFORM "ios" CACHE STRING "Simulator platform for the slice (ios, watchos, tvos, xros)")

enable_testing()

# Dobby, the default inline-hook backend, fetched at a pinned commit and linked
# as a real target. FetchContent builds the correct slice per build tree, so
# there is no archive globbing, no rpath handling, and no separate fetch script.
include(FetchContent)
set(DOBBY_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(DOBBY_BUILD_TEST OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  dobby
  GIT_REPOSITORY https://github.com/jmpews/Dobby.git
  GIT_TAG 5dfc8546954ce3b3198132ab13fddb89ee92cdd7
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(dobby)

# We link Dobby's static libs, not its shared framework. Disable the framework on
# the shared target so CMake does not recreate its Headers symlink on every
# regenerate, which fails once the symlink exists.
if(TARGET dobby)
  set_target_properties(dobby PROPERTIES FRAMEWORK FALSE)
endif()

# Dobby's static library is split across component libs (the symbol resolver, the
# mach-o kits, and the OS/logging base). Bundle them behind one interface target
# so the interposer links a single self-contained name with no runtime dylib.
add_library(dobby_bundle INTERFACE)
# Dobby is C++, so its consumers need libc++; the static components do not pull
# it in the way the shared dobby dylib would.
target_link_libraries(dobby_bundle INTERFACE
  dobby_static dobby_symbol_resolver macho_ctx_kit shared_cache_ctx_kit osbase logging c++)
target_include_directories(dobby_bundle INTERFACE ${dobby_SOURCE_DIR}/include)

add_subdirectory(packages/protocol/c)
add_subdirectory(packages/interpose)
