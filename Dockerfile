FROM ubuntu:21.04

# define the folder where our src should exist/ be deposited
ARG SRC=/python-seal

# prevents update and install asking for tz
ENV DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt update && \
    apt install -y git build-essential cmake python3 python3-dev python3-pip && \
    mkdir -p ${SRC}

# copy into container requirements and install them before rest of code
COPY ./requirements.txt ${SRC}/.
RUN pip3 install -r ${SRC}/requirements.txt

# copy everything into container now that requirements stage is complete
COPY . ${SRC}

# setting our default directory to the one specified above
WORKDIR ${SRC}

# update submodules
RUN cd ${SRC} && \
    git submodule update --init --recursive
    # git submodule update --remote

# build and install seal + bindings
RUN cd ${SRC}/SEAL && \
    cmake -S . -B build -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF && \
    cmake --build build && \
    cd ${SRC} && \
    python3 setup.py build_ext -i

CMD ["/usr/bin/python3"]
