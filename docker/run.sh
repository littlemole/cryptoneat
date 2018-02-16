!/bin/bash

echo "**********************************"
echo "building cryptoneat with $CXX"
echo "**********************************"

cd /usr/local/src/cryptoneat
make clean
make -e test
make clean
make -e install

