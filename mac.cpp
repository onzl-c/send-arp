#include "mac.h"

uint8_t* setMac(const string& mac) {
    static uint8_t mac_addr[6];
    sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_addr[0], &mac_addr[1], &mac_addr[2],
           &mac_addr[3], &mac_addr[4], &mac_addr[5]);
    return mac_addr;
}

// 외부에서 가져온 코드
uint8_t* getMyMac(const char* interface_name) {
    static char mac_str[18];

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return nullptr;
    }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return nullptr;
    }   
    close(sock);

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return setMac(mac_str);
}
