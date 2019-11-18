## Microsoft SEAL For Python

Microsoft [**SEAL**](https://github.com/microsoft/SEAL) is an easy-to-use open-source ([MIT licensed](https://github.com/microsoft/SEAL/blob/master/LICENSE)) homomorphic encryption library developed by the Cryptography Research group at Microsoft.

[**pybind11**](https://github.com/pybind/pybind11) is a lightweight header-only library that exposes C++ types in Python and vice versa, mainly to create Python bindings of existing C++ code.



## Contents

* [Build](https://github.com/Huelse/pyseal#build)
* [Tests](https://github.com/Huelse/pyseal#tests)
* [About](https://github.com/Huelse/pyseal#about)
* [Contributing](https://github.com/Huelse/pyseal#contributing)



## Build

* ### Environment

  CMake (>= 3.10), GNU G++ (>= 6.0) or Clang++ (>= 5.0), Python (>=3.6.8)

  `sudo apt-get update && sudo apt-get install g++ make git python3 python3-dev python3.6-pip`

  `git clone https://github.com/Huelse/SEAL-Python.git`

* ### SEAL 3.3.2

  ```shell
  cd SEAL/native/src
  cmake .
  make
  sudo make install
  ```

* ### pybind11

  ```
  pip3 install pytest
  
  cd pybind11
  mkdir build
  cd build
  cmake ..
  make check -j 4
  sudo make install # or not
  ```
  
* ### SEAL-Python

  ```
  cd src
  pip3 install -r requirements.txt
  
  python3 setup.py build_ext -i
  ```

* ### Others

    If you clone a new SEAL lib from the [Github](https://github.com/microsoft/SEAL), do not forget add a function set_scale in `seal/ciphertext.h` line 632, like this:

    ```c++
    /**
    Set the scale.
    */
    inline void set_scale(double scale)
    {
      scale_ = scale;
    }
    ```

    The setuptools will build a dynamic Link Library in project folder, named like `seal.cpython-36m-x86_64-linux-gnu.so`.

    You can use the CMake to build it, I have already written the `CMakelists.txt`. Make sure the SEAL and the pybind11 is correctly installed.
    
    The path is very important, please check it before you do anything.



## Tests

`cd tests`

`python3 [example_name].py`

* The `.so` file need in the same folder, or you had `make install` it already.



## Getting Started

| C++               | Python           | Description                                                  | Progress |
| ----------------- | ---------------- | ------------------------------------------------------------ | -------- |
| 1_bfv_basics.cpp  | 1_bfv_basics.py  | Encrypted modular arithmetic using the BFV scheme            | Finished |
| 2_encoders.cpp    | 2_encoders.py    | Encoding more complex data into Microsoft SEAL plaintext objects | Finished |
| 3_levels.cpp      | 3_levels.py      | Introduces the concept of levels; prerequisite for using the CKKS scheme | Finished |
| 4_ckks_basics.cpp | 4_ckks_basics.py | Encrypted real number arithmetic using the CKKS scheme       | Finished |
| 5_rotation.cpp    | 5_rotation.py    | Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes | Finished |
| 6_performance.cpp | 6_performance.py | Performance tests for Microsoft SEAL                         | Finished |



## About

This project is still testing now, if any errors occurred, new an [Issue](https://github.com/Huelse/SEAL-Python/issues) please.

Here is a compiled dynamic link library [build in ubuntu18.04](https://drive.google.com/file/d/1QZzKYjwI543gk1ltw11753zqN1OD83I3/view?usp=sharing).

If you are interested, come and join us.

Email: [huelse@oini.top](mailto:huelse@oini.top?subject=Github-SEAL-Python-Issues&cc=5956877@qq.com)



## Contributing
* Instructor: [Dr. Chen](http://blog.sciencenet.cn/u/chzg99)

