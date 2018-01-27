CXX = g++
DESTDIR=/
PREFIX=/usr/local

LIBNAME = cryptoneat
LIB = ./lib$(LIBNAME).a
LIBINC = ./include


#################################################
# rule to compile all (default rule)
#################################################

all: $(LIB)


#################################################
# actual build rules
#################################################

$(LIB): ## make the library $(LIB)
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

install: release 
	-rm -rf $(DESTDIR)/$(PREFIX)/include/$(LIBINC)
	cp -r $(LIBINC) $(DESTDIR)/$(PREFIX)/include/$(LIBNAME)
	cp $(LIB) $(DESTDIR)/$(PREFIX)/lib
	cp $(LIBNAME).pc $(DESTDIR)/$(PREFIX)/lib/pkgconfig/
	

remove: 
	-rm -rf $(DESTDIR)/$(PREFIX)/include/$(LIBNAME)
	-rm $(DESTDIR)/$(PREFIX)/lib/$(LIB)
	-rm $(DESTDIR)/$(PREFIX)/lib/pkgconfig/$(LIBNAME).pc
	
release: clean ## make release build
	cd src && make release -e -f Makefile 
	cd t && make release -e -f Makefile 

