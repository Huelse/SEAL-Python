cmake_minimum_required(VERSION 3.10.0)
project(seal)
SET(CMAKE_BUILD_TYPE "Release")
SET(PYBIND11_CPP_STANDARD -std=c++1z)

include_directories("/usr/include/python3.6")
include_directories("../pybind11/include")
include_directories("../SEAL/native/src")

LINK_LIBRARIES("../SEAL/native/lib/libseal.a")

add_subdirectory(pybind11)
pybind11_add_module(seal wrapper.cpp)