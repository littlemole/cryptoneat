# This is a comment
FROM ubuntu:24.04
LABEL AUTHOR="me <little.mole@oha7.org>"

# std dependencies
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git sudo joe wget netcat-traditional psmisc curl \
  build-essential g++ cmake pkg-config valgrind \
  libgtest-dev  openssl libssl-dev uuid-dev \
  clang libboost-dev libboost-system-dev \
  libc++-dev libc++abi-dev

ARG CXX=g++
ENV CXX=${CXX}

ARG WITH_TEST=On
ENV WITH_TEST=${WITH_TEST}

RUN echo -e "BUILDING FOR $CXX"

RUN mkdir -p /usr/local/src/cryptoneat
ADD . /usr/local/src/cryptoneat

ARG BUILDCHAIN=make
ENV BUILDCHAIN=${BUILDCHAIN}

RUN /usr/local/src/cryptoneat/docker/run.sh

