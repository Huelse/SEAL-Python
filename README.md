# pyseal

### Microsoft SEAL For Python

1. First, git clone the latest lib.

SEAL( 3.3 ) `gti clone https://github.com/microsoft/SEAL.git`

pybind11( 2.3.0 ) `gti clone https://github.com/pybind/pybind11.git`

2. Compiler the SEAL

```shell
cd SEAL/native/src
cmake .
make
sudo make install
```

3. Install the pybind11 with pip

`pip3 install -r requirements.txt`

4. Run the setup or make

`python3 setup.py build_ext -i`

or

```shell
mkdir build
cd build
cmake ..
make
```

5. Test

`python3 test.py`

6. About

This is project is building now.

If you have interest in this, come and join us.

Email: [huelse@oini.top](huelse@oini.top)