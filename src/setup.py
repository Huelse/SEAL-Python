import os, sys
from distutils.core import setup, Extension
from distutils import sysconfig

cfg_vars = sysconfig.get_config_vars()
for key, value in cfg_vars.items():
    if type(value) == str:
        cfg_vars[key] = value.replace('-Wstrict-prototypes', '')

cpp_args = ['-std=c++17']

ext_modules = [
    Extension(
        'seal',
        ['wrapper.cpp'],
        include_dirs=['/usr/include/python3.6', '../pybind11/include', '../SEAL/native/src'],
        language='c++',
        extra_compile_args = cpp_args,
        extra_objects=['../SEAL/native/lib/libseal.a'],
    ),
]

setup(
    name='seal',
    version='3.3.1',
    author='Huelse', 
    author_email='huelse@oini.top',
    description='Python wrapper for SEAL',
    ext_modules=ext_modules,
)
