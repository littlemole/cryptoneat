cmake_minimum_required(VERSION 2.8.9)
project(cryptoneat)
include(CTest)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")

add_library(cryptoneat STATIC ${SOURCES})

add_executable(Tests t/test.cpp)

IF (UNIX)

target_link_libraries(Tests gtest cryptoneat ssl crypto pthread uuid)

ELSEIF (WIN32)

target_link_libraries(Tests gtest cryptoneat ssl crypto)

ENDIF ()

add_test(NAME AllTests COMMAND Tests)

file(COPY pem DESTINATION .)
 
install(TARGETS cryptoneat DESTINATION /usr/local/lib)

install(FILES ${HEADERS} DESTINATION include/cryptoneat)

install(FILES cryptoneat.pc DESTINATION /usr/local/lib/pkgconfig)
