# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/arjun/Desktop/J-Sentinel/cpp-parser

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/arjun/Desktop/J-Sentinel/cpp-parser/build

# Include any dependencies generated for this target.
include CMakeFiles/cpp_scanner.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/cpp_scanner.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/cpp_scanner.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/cpp_scanner.dir/flags.make

CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o: CMakeFiles/cpp_scanner.dir/flags.make
CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o: ../cpp_scanner.cpp
CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o: CMakeFiles/cpp_scanner.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/arjun/Desktop/J-Sentinel/cpp-parser/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o -MF CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o.d -o CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o -c /home/arjun/Desktop/J-Sentinel/cpp-parser/cpp_scanner.cpp

CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/arjun/Desktop/J-Sentinel/cpp-parser/cpp_scanner.cpp > CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.i

CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/arjun/Desktop/J-Sentinel/cpp-parser/cpp_scanner.cpp -o CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.s

# Object files for target cpp_scanner
cpp_scanner_OBJECTS = \
"CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o"

# External object files for target cpp_scanner
cpp_scanner_EXTERNAL_OBJECTS =

cpp_scanner: CMakeFiles/cpp_scanner.dir/cpp_scanner.cpp.o
cpp_scanner: CMakeFiles/cpp_scanner.dir/build.make
cpp_scanner: /usr/lib/llvm-14/lib/libclangTooling.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangBasic.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangAST.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangASTMatchers.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangFrontend.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangSerialization.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangParse.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangSema.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangAnalysis.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangEdit.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangLex.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangDriver.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangFormat.a
cpp_scanner: /usr/lib/x86_64-linux-gnu/libcurl.so
cpp_scanner: /usr/lib/llvm-14/lib/libclangASTMatchers.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangAST.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangToolingInclusions.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangToolingCore.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangRewrite.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangLex.a
cpp_scanner: /usr/lib/llvm-14/lib/libclangBasic.a
cpp_scanner: /usr/lib/llvm-14/lib/libLLVM-14.so.1
cpp_scanner: CMakeFiles/cpp_scanner.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/arjun/Desktop/J-Sentinel/cpp-parser/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable cpp_scanner"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/cpp_scanner.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/cpp_scanner.dir/build: cpp_scanner
.PHONY : CMakeFiles/cpp_scanner.dir/build

CMakeFiles/cpp_scanner.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/cpp_scanner.dir/cmake_clean.cmake
.PHONY : CMakeFiles/cpp_scanner.dir/clean

CMakeFiles/cpp_scanner.dir/depend:
	cd /home/arjun/Desktop/J-Sentinel/cpp-parser/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/arjun/Desktop/J-Sentinel/cpp-parser /home/arjun/Desktop/J-Sentinel/cpp-parser /home/arjun/Desktop/J-Sentinel/cpp-parser/build /home/arjun/Desktop/J-Sentinel/cpp-parser/build /home/arjun/Desktop/J-Sentinel/cpp-parser/build/CMakeFiles/cpp_scanner.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/cpp_scanner.dir/depend

