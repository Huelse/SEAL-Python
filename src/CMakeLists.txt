cmake_minimum_required(VERSION 3.12.0)
project(seal)
set(CMAKE_BUILD_TYPE "Release")
set(PYBIND11_CPP_STANDARD -std=c++1z)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/../tests)

include_directories("/usr/include/python3.6")
include_directories("../pybind11/include")
include_directories("../SEAL/native/src")

LINK_LIBRARIES("../SEAL/native/lib/libseal.a")

find_package(pybind11 REQUIRED)
aux_source_directory(. DIR_SRCS)
pybind11_add_module(seal ${DIR_SRCS})