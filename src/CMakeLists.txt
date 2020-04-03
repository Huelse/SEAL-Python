cmake_minimum_required(VERSION 3.12.0)
project(seal)
set(CMAKE_BUILD_TYPE "Release")
set(PYBIND11_CPP_STANDARD -std=c++1z)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../tests)

# Confirm your python version
include_directories("/usr/include/python3.6")
include_directories("../pybind11/include")
include_directories("../SEAL/native/src")

# LINK_LIBRARIES("../SEAL/native/lib/libseal.so")
find_package(SEAL 3.4.5 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    PATHS ${seal_SOURCE_DIR}/../SEAL/src/cmake
)

find_package(pybind11 REQUIRED)

pybind11_add_module(seal wrapper.cpp)
