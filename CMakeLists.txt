cmake_minimum_required(VERSION 3.10)
project(IPv6PacketProject)

# 设置 C++ 标准为 C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 在 CentOS 中查找 libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# 包含 libpcap 的头文件目录
include_directories(${PCAP_INCLUDE_DIRS})

# 源文件
set(SOURCES IPv6Packet.cpp main.cpp)

# 设置可执行文件的输出目录为 ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin)

# 生成可执行文件
add_executable(ipv6_packet ${SOURCES})

# 链接 libpcap 库
target_link_libraries(ipv6_packet ${PCAP_LIBRARIES})