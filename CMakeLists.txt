cmake_minimum_required(VERSION 2.8.9)
project(cryptoneat)
include(CTest)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

############################################
# clang support
############################################

set(LINKERFLAGS "")
set(STDLIB "")
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(STDLIB "c++abi")
    set(LINKERFLAGS "-stdlib=libc++ -fcoroutines-ts  -std=c++14")
    set(FLAGS "-stdlib=libc++ -fcoroutines-ts -D_RESUMABLE_FUNCTIONS_SUPPORTED")
endif()

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${LINKERFLAGS}" )

find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")

add_compile_options("-O3 ${FLAGS}")

add_library(cryptoneat STATIC ${SOURCES})

add_executable(Tests t/test.cpp)

IF (UNIX)

    SET(LIBS "pthread" "uuid" ${STDLIB})

ELSEIF (WIN32)

    SET(LIBS "Ws2_32" "Rpcrt4" ${STDLIB})

ENDIF ()

target_link_libraries(Tests cryptoneat ${GTEST_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBS} )

add_test(NAME AllTests COMMAND Tests)

file(COPY pem DESTINATION .)
 
install(TARGETS cryptoneat DESTINATION lib)

install(FILES ${HEADERS} DESTINATION include/cryptoneat)

install(FILES cryptoneat.pc DESTINATION lib/pkgconfig)
