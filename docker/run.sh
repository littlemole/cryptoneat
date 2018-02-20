#!/bin/bash

if [ "$CXX" == "g++" ]
then 
        FLAGS=""
else
        FLAGS="-stdlib=libc++"
fi

echo "**********************************"
echo "building cryptoneat with" 
echo "$CXX using $BUILDCHAIN"
echo "FLAGS= $FLAGS"
echo "**********************************"

cd /usr/local/src/cryptoneat

if [ "$BUILDCHAIN" == "make" ] 
then
    make clean
    make -e test
    make clean
    make -e install
else

    mkdir build
    cd build
    cmake .. -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS=$FLAGS
    make -e
    make -e test
    make -e install
fi
