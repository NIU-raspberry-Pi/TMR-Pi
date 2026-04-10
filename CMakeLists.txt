cmake_minimum_required(VERSION 3.20.0)
project(TMR-Pi VERSION 0.0.0)

set(CMAKE_CXX_STANDARD 17)
find_package(Threads REQUIRED)

add_executable(worker_node src/worker.cpp src/Anetwork.cpp)
target_link_libraries(worker_node PRIVATE Threads::Threads)

add_executable(voter_node src/voter.cpp src/Anetwork.cpp)
target_link_libraries(voter_node PRIVATE Threads::Threads)

# install(TARGETS worker_node voter_node DESTINATION bin)