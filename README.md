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
* #### Linux
  Clang++ (>= 5.0) or GNU G++ (>= 6.0), CMake (>= 3.12)

  ```shell
  # Optional
  sudo apt-get install git build-essential cmake python3 python3-dev python3-pip

  # Get the repository or download from the releases
  git clone https://github.com/Huelse/SEAL-Python.git
  cd SEAL-Python

  # Numpy is essential
  pip3 install -r requirements.txt

  # Init the SEAL and pybind11
  git submodule update --init --recursive
  # Get the newest repositories (unnecessary)
  # git submodule update --remote

  # Build the SEAL lib
  cd SEAL
  cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
  cmake --build build
  cd ..

  # Run the setup.py
  python3 setup.py build_ext -i
  ```

* #### Windows

  Visual Studio 2019 or newer is required. And use the **x64 Native Tools Command Prompt for Visual Studio 2019**  command prompt to configure and build the Microsoft SEAL library. It's usually can be found in your Start Menu.

  ```shell
  # Same as above
  # Build the SEAL library
  cmake -S . -B build -G Ninja -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
  cmake --build build

  # Run the setup.py
  python setup.py build_ext -i
  ```

  Generally, the Ninja generator is better than the "Visual Studio 16 2019" generator, and there is more information in the Microsoft SEAL official [illustrate](https://github.com/microsoft/SEAL#building-microsoft-seal-manually).


* #### Docker
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

* #### Serialize

  In most situations, you can use the SEAL's native serialize API to save the data, here is an example:

  ```python
  cipher.save('cipher')

  load_cipher = Ciphertext()
  load_cipher.load(context, 'cipher')  # work if the context is valid.
  ```

  Support type: `Encryptionparams, Ciphertext, Plaintext, SecretKey, Publickey, Relinkeys, Galoiskeys`

  Particularly, if you want to use the pickle to serialize your data, you need to do these things like below:

  ```shell
  # 1. Modify the serializable object's header file in SEAL and switch the wrapper.
  python helper.py

  # 2. Rebuild the SEAL lib like above
  cmake --build build

  # 3. Run the setup.py
  python setup.py build_ext -i
  ```

  Then, you can pickle the data object like this:

  ```python
  import pickle

  cipher.set_parms(parms)  # necessary
  cipher_dump = pickle.dumps(cipher)
  cipher_load = pickle.loads(cipher_dump)
  ```

  Generally, we don't use compression library.

* #### Other

  There are a lot of changes in the latest SEAL lib, we try to make the API in python can be used easier, it may remain some problems we unknown, if any problems(bugs), [Issue](https://github.com/Huelse/SEAL-Python/issues) please.

  Email: [huelse@oini.top](mailto:huelse@oini.top?subject=Github-SEAL-Python-Issues)



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



## Contributing
* Professor: [Dr. Chen](https://zhigang-chen.github.io/)

* [Contributors](https://github.com/Huelse/SEAL-Python/graphs/contributors)
