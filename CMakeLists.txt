cmake_minimum_required(VERSION 3.20.0)
project(TMR-Pi VERSION 0.0.0)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS "src/*.cpp")

add_executable(${PROJECT_NAME} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto threads)

install(TARGETS ${PROJECT_NAME})