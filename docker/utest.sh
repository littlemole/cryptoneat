#!/bin/bash
set -e

if [ "$WITH_TEST" == "On" ]
then

	cd /usr/src/

	git clone https://github.com/sheredom/utest.h.git utest

	cd utest

	cp utest.h /usr/local/include/

fi

