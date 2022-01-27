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
extra_objects = ['./SEAL/build/lib/libseal-3.7.a']
# available wrapper: src/wrapper.cpp, src/wrapper_with_pickle.cpp
wrapper_file = 'src/wrapper.cpp'

if(platform.system() == "Windows"):
    cpp_args[0] = '/std:c++latest'  # /std:c++1z
    extra_objects[0] = './SEAL/build/lib/Release/seal-3.7.lib'

if not os.path.exists(extra_objects[0]):
    print('Can not find the seal lib,')
    print('Compile the seal lib first or check the path.')
    exit(1)

ext_modules = [
    Extension(
        name='seal',
        sources=[wrapper_file, 'src/base64.cpp'],
        include_dirs=include_dirs,
        language='c++',
        extra_compile_args=cpp_args,
        extra_objects=extra_objects,
    ),
]

setup(
    name='seal',
    version='3.7',
    author='Desilo',
    author_email='engineering.dev@desilo.ai',
    description='Python wrapper for the Microsoft SEAL',
    url='https://github.com/Desilo/SEAL-Python',
    license='MIT',
    ext_modules=ext_modules,
)
