cmake_minimum_required(VERSION 3.10)
project(CppScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find LLVM and Clang
find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

# Get LLVM and Clang related variables
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using ClangConfig.cmake in: ${Clang_DIR}")

# Include directories
include_directories(${LLVM_INCLUDE_DIRS})
include_directories(${CLANG_INCLUDE_DIRS})

# Definitions
add_definitions(${LLVM_DEFINITIONS})

# Find CURL
find_package(CURL REQUIRED)

add_executable(cpp_scanner cpp_scanner.cpp)
target_include_directories(cpp_scanner PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

target_link_libraries(cpp_scanner PRIVATE
    clangTooling
    clangBasic
    clangAST
    clangASTMatchers
    clangFrontend
    clangSerialization
    clangParse
    clangSema
    clangAnalysis
    clangEdit
    clangLex
    clangDriver
    clangFormat
    ${CURL_LIBRARIES}
    ${LLVM_LIBRARIES}
)