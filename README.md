## Microsoft SEAL For Python

Microsoft [**SEAL**](https://github.com/microsoft/SEAL) is an easy-to-use open-source ([MIT licensed](https://github.com/microsoft/SEAL/blob/master/LICENSE)) homomorphic encryption library developed by the Cryptography Research group at Microsoft.

[**pybind11**](https://github.com/pybind/pybind11) is a lightweight header-only library that exposes C++ types in Python and vice versa, mainly to create Python bindings of existing C++ code.

This is a python binding for the Microsoft SEAL library.



## Contents

* [Build](#build)
* [Note](#note)
  * [Serialize](#serialize)
  * [Other](#other)
* [FAQ](#faq)



## Build

* ### Linux

  Recommend: Clang++ (>= 10.0) or GNU G++ (>= 9.4), CMake (>= 3.16)

  ```shell
  # Optional
  sudo apt-get install git build-essential cmake python3 python3-dev python3-pip

  # Get the repository or download from the releases
  git clone https://github.com/Huelse/SEAL-Python.git
  cd SEAL-Python

  # Install dependencies
  pip3 install numpy pybind11

  # Init the SEAL and pybind11
  git submodule update --init --recursive
  # Get the newest repositories (dev only)
  # git submodule update --remote

  # Build the SEAL lib
  cd SEAL
  cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF
  cmake --build build
  cd ..

  # Run the setup.py
  python3 setup.py build_ext -i

  # Test
  cp seal.*.so examples
  python3 4_bgv_basics.py
  ```

  Build examples (after `cmake -S . -B`): `-DSEAL_BUILD_EXAMPLES=ON` 

  Zstandard compression off: `-DSEAL_USE_ZSTD=OFF`

  [More cmake options](https://github.com/microsoft/SEAL#basic-cmake-options)


* ### Windows

  Visual Studio 2019 or newer is required. And use the **x64 Native Tools Command Prompt for VS**  command prompt to configure and build the Microsoft SEAL library. It's usually can be found in your Start Menu.

  ```shell
  # Same as above
  # Run in "x64 Native Tools Command Prompt for VS" command prompt
  cmake -S . -B build -G Ninja -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF
  cmake --build build

  pip install numpy pybind11

  python setup.py build_ext -i
  ```

  Microsoft SEAL official [docs](https://github.com/microsoft/SEAL#building-microsoft-seal-manually).


* ### Docker

  requires: [Docker](https://www.docker.com/)

  To build source code into a docker image (from this directory):
  ```shell
  docker build -t huelse/seal -f Dockerfile .
  ```

  To use the image by running it as an interactive container:
  ```shell
  docker run -it huelse/seal
  ```



## Note

* ### Serialize

  In most situations, you can use the SEAL's native serialize API to save the data, here is an example:

  ```python
  cipher.save('cipher')

  load_cipher = Ciphertext()
  load_cipher.load(context, 'cipher')  # work if the context is valid.
  ```

  Supported classes: `EncryptionParameters, Ciphertext, Plaintext, SecretKey, PublicKey, RelinKeys, GaloisKeys`


* ### Other

  There are a lot of changes in the latest SEAL lib, we try to make the API in python can be used easier, but it may remain some problems unknown, if any problems or bugs, report [issues](https://github.com/Huelse/SEAL-Python/issues).

  Email: [topmaxz@protonmail.com](mailto:topmaxz@protonmail.com?subject=Github-SEAL-Python-Issues)



## FAQ

1. ImportError: undefined symbol

   Build a shared SEAL library `cmake . -DBUILD_SHARED_LIBS=ON`, and get the `libseal.so`,

   then change the path in `setup.py`, and rebuild.

2. ImportError: libseal.so... cannot find

   a. `sudo ln -s /path/to/libseal.so  /usr/lib`

   b. add `/usr/local/lib` or the `SEAL/native/lib` to `/etc/ld.so.conf` and refresh it `sudo ldconfig`

   c. build in cmake.

3. BuildError: C++17 at least

4. ModuleNotFoundError: No module named 'seal'

   The `.so` or `.pyd` file must be in the current directory, or you have `install` it already.

5. Windows Error LNK2001, RuntimeLibrary and MT_StaticRelease mismatch

   Only `x64` is supported, Choose `x64 Native Tools Command Prompt for VS`.



## Contributing

* Professor: [Dr. Chen](https://zhigang-chen.github.io/)

* [Contributors](https://github.com/Huelse/SEAL-Python/graphs/contributors)
