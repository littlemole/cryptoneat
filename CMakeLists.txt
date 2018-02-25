cmake_minimum_required(VERSION 2.8.9)
project(cryptoneat)
include(CTest)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(INSTALL_DEBUG "On")
set(INSTALL_RELEASE "On")

############################################
# macros
############################################

macro(AddCompilerFlags target flags)
    get_target_property(CF ${target} COMPILE_FLAGS)
    if(CF STREQUAL "CF-NOTFOUND")
        SET(CF "") # set to empty string
    else()
        SET(CF "${CF} ") # a space to cleanly separate from existing content
    endif()

    SET(CF "${CF} ${flags}" )
    set_target_properties(${target} PROPERTIES COMPILE_FLAGS ${CF} )
endmacro()



############################################
# clang support
############################################

set(LINKERFLAGS "")
set(STDLIB "")
set(FLAGS "")
if (${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    set(STDLIB "c++abi")
    set(LINKERFLAGS "-stdlib=libc++ -fcoroutines-ts  -std=c++14")
    set(FLAGS -stdlib=libc++ -fcoroutines-ts -D_RESUMABLE_FUNCTIONS_SUPPORTED)
endif()

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${LINKERFLAGS}" )

############################################
# os
############################################

message(">>>>>>>>> ${CMAKE_BUILD_TYPE}")
IF (UNIX)

	SET(DEBUGFLAGS "-g ")
    SET(RELEASEFLAGS "-O3 ")

	SET(LIBS "pthread" "uuid" ${STDLIB})

ELSEIF (WIN32)
	SET(DEBUGFLAGS " ")
    SET(RELEASEFLAGS "-O3 ")

    SET(LIBS "Ws2_32" "Rpcrt4" ${STDLIB})

	if( "${CMAKE_BUILD_TYPE}" STREQUAL "Release")
		set(INSTALL_DEBUG "Off")
	else()
		set(INSTALL_RELEASE "Off")
	endif()
endif()

############################################
# dependencies
############################################


find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

############################################
# sources
############################################

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")

add_compile_options("${FLAGS}")

############################################
# targets
############################################

add_library(cryptoneat STATIC ${SOURCES})
add_library(cryptoneatd STATIC ${SOURCES})

AddCompilerFlags(cryptoneat ${RELEASEFLAGS})
AddCompilerFlags(cryptoneatd ${DEBUGFLAGS})

add_executable(Tests t/test.cpp)

AddCompilerFlags(Tests ${DEBUGFLAGS})

target_link_libraries(Tests cryptoneat ${GTEST_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBS} )

############################################
# test
############################################

add_test(NAME AllTests COMMAND Tests)

file(COPY pem DESTINATION .)
 
############################################
# install
############################################

if( "${INSTALL_RELEASE}" STREQUAL "On")
	install(TARGETS cryptoneat DESTINATION lib)
endif()
if( "${INSTALL_DEBUG}" STREQUAL "On")
	install(TARGETS cryptoneatd DESTINATION lib)
endif()

install(FILES ${HEADERS} DESTINATION include/cryptoneat)

install(FILES cryptoneat.pc DESTINATION lib/pkgconfig)
