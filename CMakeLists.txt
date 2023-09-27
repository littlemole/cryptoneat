############################################
# preamble
############################################
cmake_minimum_required(VERSION 3.22)
project(cryptoneat)
#cmake_policy(SET CMP0054 NEW)
include(CTest)
set(VERSION 0.0.15)

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
set(FLAGS "")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(STDLIB "c++abi")
    set(LINKERFLAGS "-stdlib=libc++ -fcoroutines-ts  -std=c++20")
    set(FLAGS "-stdlib=libc++ -fcoroutines-ts -D_RESUMABLE_FUNCTIONS_SUPPORTED")
endif()


############################################
# OS support (Linux/Windows)
############################################

IF (WIN32)

	set(OSLIBS "Ws2_32" "Rpcrt4")

	set(BUILDFLAGS "-await ${FLAGS}")

	set(LIBS ${GTEST_LIBRARIES} ${OPENSSL_LIBRARIES} ${STDLIB}  )

	set(LIBS debug ${CMAKE_PROJECT_NAME} optimized ${CMAKE_PROJECT_NAME} ${LIBS} )


 ELSEIF (UNIX)

    set(OSLIBS "pthread" "uuid")

    set(BUILDFLAGS " ${FLAGS}")

    set(LIBS ${OPENSSL_LIBRARIES} ${STDLIB}  )

    set(LIBS debug ${CMAKE_PROJECT_NAME} optimized ${CMAKE_PROJECT_NAME} ${LIBS} )

ENDIF ()

############################################
# set linker and compiler flags
############################################

set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${LINKERFLAGS}" )
set(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG} -DMOL_PROMISE_DEBUG")
set(CMAKE_CXX_FLAGS  	    "${CMAKE_CXX_FLAGS} ${BUILDFLAGS}")


############################################
# include directories
############################################

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

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

add_executable(Tests t/test.cpp)


############################################
# libs for tests
############################################

target_link_libraries(Tests PUBLIC ${LIBS} ${OSLIBS} )


############################################
# run tests
############################################


add_test(NAME AllTests COMMAND Tests)

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
         DESTINATION ${CMAKE_INSTALL_DATADIR}/cryptoneat-${VERSION}/cmake)