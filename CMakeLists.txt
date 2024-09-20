cmake_minimum_required(VERSION 3.10)
project(IPv6PacketProject)

# 设置 C++ 标准为 C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 使用 Homebrew 安装的 libpcap
include_directories(/opt/homebrew/opt/libpcap/include)
link_directories(/opt/homebrew/opt/libpcap/lib)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -target arm64-apple-macos11")

# 包含目录
include_directories(${PCAP_INCLUDE_DIRS})

# 源文件
set(SOURCES IPv6Packet.cpp main.cpp)

# 设置可执行文件的输出目录为 ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin)

# 生成可执行文件
add_executable(ipv6_packet ${SOURCES})

# 链接 libpcap 库
target_link_libraries(ipv6_packet ${PCAP_LIBRARIES})
