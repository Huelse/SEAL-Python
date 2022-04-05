import os
import platform
from glob import glob
from setuptools import setup
from distutils.sysconfig import get_python_inc
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "4.0.0"

include_dirs = [get_python_inc(), 'pybind11/include', 'SEAL/native/src', 'SEAL/build/native/src']

extra_objects = sorted(glob('SEAL/build/lib/*.lib') if platform.system() == "Windows" else glob('SEAL/build/lib/*.a'))

cpp_args = ['/std:c++latest'] if platform.system() == "Windows" else ['-std=c++17']

if len(extra_objects) < 1 or not os.path.exists(extra_objects[0]):
    print('Not found the seal lib file, check the `SEAL/build/lib`')
    exit(0)

ext_modules = [
    Pybind11Extension(
        "seal",
        sorted(glob('src/*.cpp')),
        include_dirs=include_dirs,
        extra_compile_args=cpp_args,
        extra_objects=extra_objects,
        define_macros = [('VERSION_INFO', __version__)],
    ),
]

setup(
    name="seal",
    version=__version__,
    author="Huelse",
    author_email="topmaxz@protonmail.com",
    url="https://github.com/Huelse/SEAL-Python",
    description="Python wrapper for the Microsoft SEAL",
    long_description="",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    zip_safe=False,
    license='MIT',
    python_requires=">=3.6",
)
