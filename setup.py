import os
import platform
from glob import glob
from pathlib import Path
from shutil import copy2
from setuptools import setup
from distutils.sysconfig import get_python_inc
from pybind11.setup_helpers import Pybind11Extension, build_ext

__version__ = "4.1.2"
BASE_DIR = Path(__file__).resolve().parent

include_dirs = [get_python_inc(), 'pybind11/include', 'SEAL/native/src', 'SEAL/build/native/src']

extra_objects = sorted(glob('SEAL/build/lib/*.lib') if platform.system() == "Windows" else glob('SEAL/build/lib/*.a'))

cpp_args = ['/std:c++latest'] if platform.system() == "Windows" else ['-std=c++17']

if len(extra_objects) < 1 or not os.path.exists(extra_objects[0]):
    print('Not found the seal lib file, check the `SEAL/build/lib`')
    exit(0)


class build_ext_with_typing(build_ext):
    """Copy PEP 561 typing files next to the compiled extension."""
    typing_files = ("seal.pyi", "py.typed")

    def run(self):
        super().run()
        self._copy_typing_files()

    def _copy_typing_files(self):
        output_dirs = {Path(self.build_lib)}
        if self.inplace:
            output_dirs.add(BASE_DIR)

        for target_dir in output_dirs:
            target_dir.mkdir(parents=True, exist_ok=True)
            for filename in self.typing_files:
                source = BASE_DIR / filename
                if source.exists():
                    destination = target_dir / filename
                    if source.resolve() == destination.resolve():
                        continue
                    copy2(source, destination)


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
    name="pyseal",
    version=__version__,
    author="Huelse",
    author_email="topmaxz@protonmail.com",
    url="https://github.com/Huelse/SEAL-Python",
    description="Python wrapper for the Microsoft SEAL",
    long_description=(BASE_DIR / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext_with_typing},
    zip_safe=False,
    license='MIT',
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: C++",
        "Topic :: Security :: Cryptography",
    ],
    project_urls={
        "Repository": "https://github.com/Huelse/SEAL-Python",
        "Issues": "https://github.com/Huelse/SEAL-Python/issues",
    },
)
