############################################
# preamble
############################################

cmake_minimum_required(VERSION 3.22)


if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

project(cryptoneat)
set(VERSION 0.0.15)
include(CTest)

option(WITH_TEST "run tests (default:on)" ON)

############################################
# c++ std
############################################

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


############################################
# debug mode produces libs with d suffix
############################################

if(NOT CMAKE_DEBUG_POSTFIX)
  set(CMAKE_DEBUG_POSTFIX d)
endif()


############################################
# basic dependecies
############################################

find_package(OpenSSL REQUIRED)


############################################
# clang support
############################################

set(LINKERFLAGS "")
set(STDLIB "")
if(WIN32)
    set(FLAGS "/W3 -D_CRT_SECURE_NO_WARNINGS")
else()
    set(FLAGS "-Wall -Wextra -Wno-unused-parameter")
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(STDLIB "c++abi")
    set(LINKERFLAGS "-stdlib=libc++ -std=c++20")
    set(FLAGS "-stdlib=libc++ ")
endif()


############################################
# OS support (Linux/Windows)
############################################

IF (WIN32)

    set(OSLIBS "Ws2_32" "Rpcrt4")

ELSEIF (UNIX)

    set(OSLIBS "pthread" "uuid")

ENDIF()

set(LIBS ${OPENSSL_LIBRARIES} ${STDLIB} )
set(LIBS ${CMAKE_PROJECT_NAME} ${LIBS}  )


############################################
# set linker and compiler flags
############################################

set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${LINKERFLAGS}" )
set(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG} ")
set(CMAKE_CXX_FLAGS  	    "${CMAKE_CXX_FLAGS} ${FLAGS}")

set(INCLUDES "include")

if(WITH_TEST) 

    include(FetchContent)

	# utest
    FetchContent_Declare(
        utest
        # Specify the commit you depend on and update it regularly.
        URL https://github.com/sheredom/utest.h/archive/25c4a9d78df0fb12e6c5364bc811f7f675e9dcb3.zip
    )

	FetchContent_GetProperties(utest)
    if(NOT utest_POPULATED)
        FetchContent_Populate(utest)
    endif()
	
	set(INCLUDES "include" "${CMAKE_BINARY_DIR}/_deps/utest-src/")

endif()

############################################
# include directories
############################################

include_directories(${INCLUDES})
include_directories(${OPENSSL_INCLUDE_DIR})
message("INC: ${OPENSSL_INCLUDE_DIR}")

############################################
# sources
############################################

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")


############################################
# lib target
############################################

add_library(cryptoneat STATIC ${SOURCES})


############################################
# tests
############################################

if(WITH_TEST)

add_executable(Tests t/test.cpp)


############################################
# libs for tests
############################################

target_link_libraries(Tests PUBLIC ${LIBS} ${OSLIBS} )


############################################
# run tests
############################################

add_test(NAME AllTests COMMAND Tests)

endif()

file(COPY pem DESTINATION .)

 
############################################
# install
############################################

install(TARGETS cryptoneat DESTINATION lib EXPORT cryptoneat-targets)

install(DIRECTORY include/cryptoneat DESTINATION include)

install(FILES cryptoneat.pc DESTINATION lib/pkgconfig)

install(EXPORT cryptoneat-targets DESTINATION lib/cryptoneat-${VERSION})

############################################
# Create and install package configuration 
# and version files.
############################################

configure_file(
   ${cryptoneat_SOURCE_DIR}/cryptoneat-config.cmake.in
   ${cryptoneat_BINARY_DIR}/cryptoneat-config.cmake @ONLY)

configure_file(
   ${cryptoneat_SOURCE_DIR}/cryptoneat-config-version.cmake.in
   ${cryptoneat_BINARY_DIR}/cryptoneat-config-version.cmake @ONLY)

install(FILES ${cryptoneat_BINARY_DIR}/cryptoneat-config.cmake
         ${cryptoneat_BINARY_DIR}/cryptoneat-config-version.cmake
         DESTINATION lib/cryptoneat-${VERSION})


############################################
# packaging
############################################

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
include(package)
         
         
