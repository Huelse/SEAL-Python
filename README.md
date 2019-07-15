# pySEAL

### Microsoft SEAL For Python

1. First, git clone the latest lib.

`gti clone https://github.com/microsoft/SEAL.git`

`gti clone https://github.com/pybind/pybind11.git`

2. Compiler the SEAL

```
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

```
mkdir build
cd build
cmake ..
make
```

