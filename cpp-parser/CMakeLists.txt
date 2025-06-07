cmake_minimum_required(VERSION 3.10)
project(CppScanner)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)
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
    clangASTMatchers
    ${CURL_LIBRARIES}
)
target_compile_definitions(cpp_scanner PRIVATE ${LLVM_DEFINITIONS})