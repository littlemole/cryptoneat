cmake_minimum_required(VERSION 2.8.9)
project(cryptoneat)
include(CTest)

IF (WIN32)
find_package(gtest REQUIRED)
find_package(openssl REQUIRED)
ENDIF ()


set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB SOURCES "src/*.cpp")
file(GLOB HEADERS "include/cryptoneat/*.h")

add_library(cryptoneat STATIC ${SOURCES})

add_executable(Tests t/test.cpp)

IF (UNIX)

target_link_libraries(Tests gtest cryptoneat ssl crypto pthread uuid)

ELSEIF (WIN32)

target_link_libraries(Tests ${GTEST_LIBRARY} cryptoneat ${OPENSSL_LIBRARIES} Ws2_32 Rpcrt4 )

ENDIF ()

add_test(NAME AllTests COMMAND Tests)

file(COPY pem DESTINATION .)
 
install(TARGETS cryptoneat DESTINATION lib)

install(FILES ${HEADERS} DESTINATION include/cryptoneat)

install(FILES cryptoneat.pc DESTINATION lib/pkgconfig)
