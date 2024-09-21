#include "IPv6Packet.h"

int main() {
    // 目标 IPv6 地址和用户数据
    std::string dst_addr = "240e:608:702:8000:59d7:1328:4cf9:dd7a"; // 替换为实际的目标 IPv6 地址
    std::string user_data = "This is a test message.";

    // 构建 IPv6 数据包
    IPv6Packet packet(dst_addr, user_data);

    // 构建数据包
    packet.buildPacket();

    // 打印数据包信息
    packet.printPacketInfo();

    // 发送数据包 10 次
    packet.sendPackets(20);

    return 0;
}

//g++ -o ipv6_sender main.cpp IPv6Packet.cpp -lpcap