DEBUG = -g 
release : override DEBUG = -O3

LIB = ../libcryptoneatd.a
release : override LIB = ../libcryptoneat.a

DEFAULT_OPTS = -std=c++20
DEFAULT_LIBS = 

ifneq ($(CXX),g++)
DEFAULT_LIBS = -stdlib=libc++ -lc++abi -std=c++20
DEFAULT_OPTS = -std=c++20 -stdlib=libc++ -D_RESUMABLE_FUNCTIONS_SUPPORTED 
endif

OPTIONS = -fpic -Wno-write-strings -pthread -D_REENTRANT $(DEFAULT_OPTS)

TESTFLAGS = -g

TEST_SRC   = .
TEST_BUILD = ./build

CPPFLAGS = -Wall -I../include $(DEBUG) $(REENTRANT) $(OPTIONS) 
DEPS = -lssl -lcrypto -lpthread

TEST_LIBS  = $(LIB) -luuid  $(DEPS) $(DEFAULT_LIBS)


# Objects for the test executable
TEST_SRCFILESABS = $(shell ls $(TEST_SRC)/*.cpp)
TEST_SRCFILES =  $(notdir $(TEST_SRCFILESABS))
TEST_OBJFILES = $(TEST_SRCFILES:%.cpp=$(TEST_BUILD)/%.o)

TEST_BINS = $(TEST_SRCFILES:%.cpp=$(TEST_BUILD)/%.bin)

#################################################
# rule to compile all (default rule)
#################################################

all: utest.h $(TEST_BINS)

utest.h:
	curl https://raw.githubusercontent.com/sheredom/utest.h/25c4a9d78df0fb12e6c5364bc811f7f675e9dcb3/utest.h > utest.h

#################################################
# rules to compile .o files from .cpp source
#################################################

$(TEST_BUILD)/%.o: $(TEST_SRC)/%.cpp 
	-mkdir -p $(TEST_BUILD)
	$(CXX) -c $^ -o $@ $(CPPFLAGS) $(TESTFLAGS)


#################################################
# rules to compile the artifacts from .o files
#################################################

$(TEST_BUILD)/%.bin: $(TEST_BUILD)/%.o 
	$(CXX) $(LIB_OBJFILES) $^ $(TEST_LIBS) -o $@ 
			
#################################################
# make clean
#################################################

clean:
	-find -name "*.o" -exec rm {} \;
	-find -name "*.bin" -exec rm {} \;
	-find -name "*~" -exec rm {} \;


release : all


