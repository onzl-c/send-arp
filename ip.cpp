#include "ip.h"

uint32_t setIp(const std::string& ip) {
    uint32_t ip_addr = 0;
    int a, b, c, d;
    sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    ip_addr |= (a << 24) | (b << 16) | (c << 8) | d;
    return htonl(ip_addr);
}

// 외부에서 가져온 코드
uint32_t getMyIp(const char* interface_name) {
    int fd;
    struct ifreq ifr;
    struct sockaddr_in* addr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(1);
    }

    close(fd);

    // sockaddr_in 구조체로 캐스팅
    addr = (struct sockaddr_in*)&ifr.ifr_addr;

    // in_addr 구조체의 s_addr 멤버(uint32_t)를 바로 반환
    return addr->sin_addr.s_addr;
}