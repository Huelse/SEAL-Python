FROM ubuntu:19.10

# Install binary dependencies
RUN apt-get update && apt-get install -qqy g++ git make cmake python3 python3-dev python3-pip sudo libdpkg-perl --no-install-recommends

# Build SEAL libraries
RUN mkdir -p app/
COPY ./SEAL/ /app/SEAL/
COPY ./pybind11/ /app/pybind11/
COPY ./src/ /app/src/

# Build SEAL
WORKDIR /app/SEAL/native/src
RUN cmake .
RUN make
RUN make install

# Install requirements
WORKDIR /app/src
RUN pip3 install -r requirements.txt

# Build pybind11
WORKDIR /app/pybind11
RUN mkdir build
WORKDIR /app/pybind11/build
RUN cmake ..
RUN make check -j 4
RUN make install

# Build wrapper
WORKDIR /app/src
RUN python3 setup.py build_ext -i
RUN python3 setup.py install

# Clean-up
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
