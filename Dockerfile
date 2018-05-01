# This is a comment
FROM ubuntu:18.04
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

# compile gtest with given compiler
RUN  cd /usr/src/gtest && \
  if [ "$CXX" = "g++" ] ; then \
  cmake .; \
  else \
  cmake -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="-std=c++14 -stdlib=libc++" . ; \
  fi && \
  make && \
  ln -s /usr/src/gtest/libgtest.a /usr/lib/libgtest.a && \
  ln -s /usr/src/gtest/libgtest_main.a /usr/lib/libgtest_main.a


RUN mkdir -p /usr/local/src/cryptoneat
ADD . /usr/local/src/cryptoneat

ARG BUILDCHAIN=make
ENV BUILDCHAIN=${BUILDCHAIN}

RUN /usr/local/src/cryptoneat/docker/run.sh

