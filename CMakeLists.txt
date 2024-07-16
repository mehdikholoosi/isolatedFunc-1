# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(MyProject VERSION 1.0)

# Specify the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Compile isolated-1.c
add_executable(Isolated1 isolated-1.c)

# Compile isolated-2.c
add_executable(Isolated2 isolated-2.c)

# Compile isolated-3.c
add_executable(Isolated3 isolated-3.c)
