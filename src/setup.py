import os
import sys
import platform
from distutils.core import setup, Extension

# cpp flags
cpp_args = ['-std=c++17']
# include directories
include_dirs = ['/usr/include/python3.6',
                '../pybind11/include', '../SEAL/native/src']
# library path
extra_objects = ['../SEAL/native/lib/libseal.a']

if(platform.system() == "Windows"):
    cpp_args[0] = '/std:c++latest'
    include_dirs[0] = sys.path[4]+'\\include'
    extra_objects[0] = '../SEAL/native/lib/x64/Release/seal.lib'

if not os.path.exists(extra_objects[0]):
    print('Can not find the seal lib')
    exit(1)

ext_modules = [
    Extension(
        'seal',
        ['base64.cpp', 'wrapper.cpp'],
        include_dirs=include_dirs,
        language='c++',
        extra_compile_args=cpp_args,
        extra_objects=extra_objects,
    ),
]

setup(
    name='seal',
    version='3.3.2',
    author='Huelse',
    author_email='huelse@oini.top',
    description='Python wrapper for SEAL',
    ext_modules=ext_modules,
)
