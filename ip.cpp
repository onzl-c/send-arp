#include "ip.h"

uint32_t setIp(const std::string& ip) {
    uint32_t ip_addr = 0;
    int a, b, c, d;
    sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
    ip_addr |= (a << 24) | (b << 16) | (c << 8) | d;
    return htonl(ip_addr);
}