# pyseal

## Microsoft SEAL For Python

Tips: No matter how, the Path is very important.

### Install

1. First, git clone the latest lib.

   SEAL( 3.3 ) `git clone https://github.com/microsoft/SEAL.git`

   pybind11( 2.3.0 ) `git clone https://github.com/pybind/pybind11.git`

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



### Test

`cd tests`

`python3 [example_name].py`



### Progress

| C++               | Python           | Description                                                  | Progress |
| ----------------- | ---------------- | ------------------------------------------------------------ | -------- |
| 1_bfv_basics.cpp  | 1_bfv_basics.py  | Encrypted modular arithmetic using the BFV scheme            | Finished |
| 2_encoders.cpp    | 2_encoders.py    | Encoding more complex data into Microsoft SEAL plaintext objects | Error    |
| 3_levels.cpp      | 3_levels.py      | Introduces the concept of levels; prerequisite for using the CKKS scheme | Building |
| 4_ckks_basics.cpp | 4_ckks_basics.py | Encrypted real number arithmetic using the CKKS scheme       | Building |
| 5_rotation.cpp    | 5_rotation.py    | Performing cyclic rotations on encrypted vectors in the BFV and CKKS schemes | Building |
| 6_performance.cpp | 6_performance.py | Performance tests for Microsoft SEAL                         | Building |



### About

This is project is building now.

If you have interest in this, come and join us.

Email: [huelse@oini.top](mailto:huelse@oini.top)



### Contributors
* 指导老师：陈智罡
