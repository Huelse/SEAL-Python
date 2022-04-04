import os
import platform
from setuptools import setup, Extension
from distutils.sysconfig import get_python_inc


# python include dir
py_include_dir = os.path.join(get_python_inc())
# cpp flags
cpp_args = ['-std=c++17']
# include directories
include_dirs = [py_include_dir, './pybind11/include', './SEAL/native/src', './SEAL/build/native/src']
# library path
extra_objects = ['./SEAL/build/lib/libseal-4.0.a']
# available wrapper: src/wrapper.cpp, src/wrapper_with_pickle.cpp
wrapper_file = 'src/wrapper.cpp'

if platform.system() == "Windows":
    cpp_args[0] = '/std:c++latest'  # /std:c++1z
    extra_objects[0] = './SEAL/build/lib/seal-4.0.lib'

if not os.path.exists(extra_objects[0]):
    print('Not found the seal lib file')
    exit(0)

ext_modules = [
    Extension(
        name='seal',
        sources=[wrapper_file],
        include_dirs=include_dirs,
        language='c++',
        extra_compile_args=cpp_args,
        extra_objects=extra_objects,
    ),
]

setup(
    name='seal',
    version='4.0',
    author='Huelse',
    author_email='huelse@oini.top',
    description='Python wrapper for the Microsoft SEAL',
    url='https://github.com/Huelse/SEAL-Python',
    license='MIT',
    ext_modules=ext_modules,
)
