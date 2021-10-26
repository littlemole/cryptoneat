
DEBUG = -g -DMOL_PROMISE_DEBUG
release : override DEBUG = -O3

DEFAULT_OPTS = -std=c++20 -D_RESUMABLE_FUNCTIONS_SUPPORTED
DEFAULT_LIBS = 

ifneq ($(CXX),g++)
DEFAULT_LIBS = -stdlib=libc++ -fcoroutines-ts  -lc++abi #-std=c++14
DEFAULT_OPTS = -std=c++20 -stdlib=libc++ -fcoroutines-ts -D_RESUMABLE_FUNCTIONS_SUPPORTED 
endif

OPTIONS = -std=c++20 -fpic -Wno-write-strings -pthread -D_REENTRANT $(DEFAULT_OPTS)

# compile flags
CPPFLAGS = -Wall -I../include $(DEBUG) $(REENTRANT) $(INCLUDE) $(OPTIONS) 


# library flags
DEPS =  -lssl -lcrypto 
LIBS =  $(DEPS) 

#################################################
# source and build path information
#################################################

# the shared lib
LIBNAME = ../lib$(shell pwd | xargs dirname | xargs basename)
LIB = $(LIBNAME)d.a
release: override LIB = $(LIBNAME).a

LIB_SRC = .
LIB_BUILD = ./build


# Objects for the static library
LIB_SRCFILESABS = $(shell ls $(LIB_SRC)/*.cpp)
LIB_SRCFILES =  $(notdir $(LIB_SRCFILESABS))
LIB_OBJFILES = $(LIB_SRCFILES:%.cpp=$(LIB_BUILD)/%.o)

#################################################
# usually no need to change anything below
#################################################

.SUFFIXES: .cpp

#################################################
# rule to compile all (default rule)
#################################################

all: $(LIB) 
	echo "----------------$(LIB)"

#################################################
# release rule 
#################################################

release: all

#################################################
# actual build rules
#################################################
	
#################################################
# rules to compile .o files from .cpp source
#################################################

$(LIB_BUILD)/%.o: $(LIB_SRC)/%.cpp 
	-mkdir -p $(LIB_BUILD)
	$(CXX) -c $^ -o $@ $(CPPFLAGS)

#################################################
# rule to compile the lib file from .o files
#################################################

$(LIB): $(LIB_OBJFILES)
	echo "Building $(LIB)"
	ar rcs $(LIB) $(LIB_OBJFILES)
	ranlib $(LIB)

		
#################################################
# make clean
#################################################

clean:
	-find -name "*~" -exec rm {} \;
	-rm -f $(LIB)
	-rm -f $(LIB_BUILD)/*.o
	
