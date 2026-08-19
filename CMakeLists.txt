cmake_minimum_required(VERSION 4.0)
project(wireSniffer)

set(CMAKE_CXX_STANDARD 20)

add_executable(wireSniffer main.cpp)


target_link_libraries(wireSniffer pcap)

