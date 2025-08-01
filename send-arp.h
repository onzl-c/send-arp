#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArp final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage();

uint8_t* send_arp_attack(pcap_t* handle, \
                    uint8_t* sender_mac, const char* sender_ip, \
                    uint8_t* target_mac, const char* target_ip, \
                    uint16_t opcode, const char* attacker_mac="00:00:00:00:00:00");