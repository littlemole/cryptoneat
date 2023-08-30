# This is a comment
FROM ubuntu:22.04
MAINTAINER me <little.mole@oha7.org>

# std dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git sudo joe wget netcat psmisc \
  build-essential g++ cmake pkg-config valgrind \
  libgtest-dev  openssl libssl-dev uuid-dev \
  clang libboost-dev libboost-system-dev \
  libc++-dev libc++abi-dev


# hack for gtest with clang++-5.0
#RUN ln -s /usr/include/c++/v1/cxxabi.h /usr/include/c++/v1/__cxxabi.h
#RUN ln -s /usr/include/libcxxabi/__cxxabi_config.h /usr/include/c++/v1/__cxxabi_config.h

ARG CXX=g++
ENV CXX=${CXX}

RUN echo -e "BUILDING FOR $CXX"

ADD ./docker/utest.sh /usr/local/bin/utest.sh
RUN /usr/local/bin/utest.sh


RUN mkdir -p /usr/local/src/cryptoneat
ADD . /usr/local/src/cryptoneat

ARG BUILDCHAIN=make
ENV BUILDCHAIN=${BUILDCHAIN}

RUN /usr/local/src/cryptoneat/docker/run.sh

