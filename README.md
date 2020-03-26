## Microsoft SEAL For Python

Microsoft [**SEAL**](https://github.com/microsoft/SEAL) is an easy-to-use open-source ([MIT licensed](https://github.com/microsoft/SEAL/blob/master/LICENSE)) homomorphic encryption library developed by the Cryptography Research group at Microsoft.

[**pybind11**](https://github.com/pybind/pybind11) is a lightweight header-only library that exposes C++ types in Python and vice versa, mainly to create Python bindings of existing C++ code.

This is a python binding for the Microsoft SEAL library.



## Contents

* [Build](https://github.com/Huelse/SEAL-Python#build)
* [Tests](https://github.com/Huelse/SEAL-Python#tests)
* [About](https://github.com/Huelse/SEAL-Python#about)
* [Contributing](https://github.com/Huelse/SEAL-Python#contributing)



## Build
### Linux
CMake (>= 3.10), GNU G++ (>= 6.0) or Clang++ (>= 5.0), Python (>=3.6.8)

`sudo apt-get update && sudo apt-get install g++ make cmake git python3 python3-dev python3.6-pip`

`git clone https://github.com/Huelse/SEAL-Python.git`

```shell
cd SEAL/native/src
cmake .
make

cd src
pip3 install -r requirements.txt

# Check the path at first
# Setuptools (Recommend)
cd src
python3 setup.py build_ext -i
# or install
python3 setup.py install

# CMake (Optional)
mkdir build
cd build
cmake ..
make
```

[setuptools docs](https://docs.python.org/3/distutils/configfile.html)

[pybind11 docs](https://pybind11.readthedocs.io/en/master/index.html)

### Windows

Visual Studio 2017 version 15.3 or newer is required to build Microsoft SEAL.

Open the `SEAL/SEAL.sln` in VS, config in `x64, Release, WinSDK(17763, etc)` mode and generate it.

```shell
cd src
python3 setup.py build_ext -i
# or install
python3 setup.py install
```

Microsoft official video [SEAL in windows](https://www.microsoft.com/en-us/research/video/installing-microsoft-seal-on-windows/).




## Tests

`cd tests`

`python3 [example_name].py`

* The `.so` file must be in the same folder, or you had `install` it already.



## Getting Started

| C++               | Python           | Description                                                  | Progress |
| ----------------- | ---------------- | ------------------------------------------------------------ | -------- |
| 1_bfv_basics.cpp  | 1_bfv_basics.py  | Encrypted modular arithmetic using the BFV scheme            | Finished |
| 2_encoders.cpp    | 2_encoders.py    | Encoding more complex data into Microsoft SEAL plaintext objects | Finished |
| 3_levels.cpp      | 3_levels.py      | Introduces the concept of levels; prerequisite for using the CKKS scheme | Finished |
| 4_ckks_basics.cpp | 4_ckks_basics.py | Encrypted real number arithmetic using the CKKS scheme       | Finished |
| 5_rotation.cpp    | 5_rotation.py    | Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes | Finished |
| 6_performance.cpp | 6_performance.py | Performance tests for Microsoft SEAL                         | Finished |



## Future

* SEAL 3.4 or higher support



## About

This project is still testing now, if any problems(bugs), [Issue](https://github.com/Huelse/SEAL-Python/issues) please.

Email: [huelse@oini.top](mailto:huelse@oini.top?subject=Github-SEAL-Python-Issues&cc=5956877@qq.com)



## Contributing
* Professor: [Dr. Chen](https://zhigang-chen.github.io/)

* [Contributors](https://github.com/Huelse/SEAL-Python/graphs/contributors)

