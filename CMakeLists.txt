cmake_minimum_required(VERSION 2.8.9)
project(cryptoneat)
include(CTest)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")

add_compile_options("-O3")

add_library(cryptoneat STATIC ${SOURCES})

add_executable(Tests t/test.cpp)

IF (UNIX)

    SET(LIBS "pthread" "uuid")

ELSEIF (WIN32)

    SET(LIBS "Ws2_32" "Rpcrt4")

ENDIF ()

target_link_libraries(Tests cryptoneat ${GTEST_LIBRARY} ${OPENSSL_LIBRARIES} ${LIBS} )


add_test(NAME AllTests COMMAND Tests)

file(COPY pem DESTINATION .)
 
install(TARGETS cryptoneat DESTINATION lib)

install(FILES ${HEADERS} DESTINATION include/cryptoneat)

install(FILES cryptoneat.pc DESTINATION lib/pkgconfig)
