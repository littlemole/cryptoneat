CXX = g++
DESTDIR=/
PREFIX=/usr/local

LIBNAME = cryptoneat
LIB = ./lib$(LIBNAME)d.a
release: override LIB = ./lib${LIBNAME}.a
LIBINC = ./include/cryptoneat

BUILDCHAIN = make
CONTAINER = $(shell echo "$(LIBNAME)_$(CXX)_$(BUILDCHAIN)" | sed 's/++/pp/')
IMAGE = littlemole/$(CONTAINER)


#################################################
# rule to compile all (default rule)
#################################################

all: $(LIB)


#################################################
# actual build rules
#################################################

$(LIB): ## make the library $(LIB)
	echo "+++++++++++$(LIB)"
	cd src && make -e -f Makefile 
	
test-build: ## make the test binaries
	cd t && make -e -f Makefile 
			
#################################################
# make clean
#################################################

clean: ## cleans up build artefacts
	cd t && make -f Makefile clean
	-find -name "*~" -exec rm {} \;
	cd src && make -f Makefile clean
	-rm -rf ./build
		
#################################################
# make test runs the unit tests
#################################################	
	
test: $(LIB) test-build ## runs unit tests
	./t/build/test.bin

build: test	
	mkdir -p ./build/include
	mkdir -p ./build/lib/pkgconfig
	cp -r include/* ./build/include/
	cp *.a ./build/lib/
	cp $(LIBNAME).pc ./build/lib/pkgconfig

#################################################
# make install copies the lib to system folders
#################################################

install: clean all
	echo "LIB:$(LIB)"
	-rm -rf $(DESTDIR)/$(PREFIX)/include/$(LIBNAME)
	cp -r $(LIBINC) $(DESTDIR)/$(PREFIX)/include/$(LIBNAME)
	cp $(LIB) $(DESTDIR)/$(PREFIX)/lib
	mkdir -p $(DESTDIR)/$(PREFIX)/lib/pkgconfig/
	cp $(LIBNAME).pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/
	make -e clean
	make -e release
	cp libcryptoneat.a  $(DESTDIR)/$(PREFIX)/lib		

remove: 
	-rm -rf $(DESTDIR)/$(PREFIX)/include/$(LIBNAME)
	-rm $(DESTDIR)/$(PREFIX)/lib/$(LIB)*
	-rm $(DESTDIR)/$(PREFIX)/lib/pkgconfig/$(LIBNAME).pc
	
release: clean ## make release build
	cd src && make release -e -f Makefile 
	cd t && make release -e -f Makefile 


# docker stable testing environment

image: ## build docker test image
	docker build -t $(IMAGE) . -fDockerfile  --build-arg CXX=$(CXX) --build-arg BUILDCHAIN=$(BUILDCHAIN)

clean-image: ## rebuild the docker test image from scratch
	docker build -t $(IMAGE) . --no-cache -fDockerfile --build-arg CXX=$(CXX) --build-arg BUILDCHAIN=$(BUILDCHAIN)
		
bash: rmc image ## run the docker image and open a shell
	docker run --name $(CONTAINER) -ti -e COMPILER=$(CXX) $(IMAGE) bash

stop: ## stop running docker image, if any
	-docker stop $(CONTAINER)
	
rmc: stop ## remove docker container, if any
	-docker rm $(CONTAINER)

rmi : ## remove existing docker image, if any
	-docker rmi $(IMAGE)



