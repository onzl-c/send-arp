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

void request_sender_mac(pcap_t* handle, uint8_t* my_mac, uint32_t my_ip, uint32_t sender_ip);
bool analysis_sender_mac(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip, uint8_t* sender_mac);
void send_arp_attack(pcap_t* handle, uint8_t* sender_mac, uint32_t sender_ip, uint32_t target_ip, uint8_t* my_mac);