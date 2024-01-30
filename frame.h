#pragma pack(push,1)
struct Radiotap {
    uint8_t it_version;
    uint8_t it_pad ;
    uint16_t it_len;
    uint32_t it_present;
    uint32_t padding[4];
}; // radiotap 24byte

struct Dot11_Frame {
    uint16_t type; //0x000c
    uint16_t duration; //0x003c
    uint8_t destination_address[6]; //FF:FF:FF:FF:FF:FF
    uint8_t source_address[6]; // AP mac
    uint8_t bssid[6];
    uint16_t fragment_num;
    uint16_t sequence_number;
}; // beacon frame 24byte

struct Fixed_Parameter {
    uint64_t timestamp;
    uint8_t beacon_interval;
    uint8_t capabilities_info;
}; // fixed 2byte


struct Tagged_SSID_Parameter {
    uint8_t number;
    uint8_t length;
    char ssid[32];
}; // taged_ssid 34byte

struct Tagged_DS_Parameter {
    uint8_t number;
    uint8_t length;
    uint8_t channel;
}; // taged_ds 3byte

struct Taged_Support_Parameter {
    uint8_t number;
    uint8_t length;
    uint8_t rates[8];
}; // taged_support 5byte

struct Taggd_Parameter{
    struct Tagged_SSID_Parameter ssid;
    struct Tagged_DS_Parameter ds;
    struct Taged_Support_Parameter support;
};

struct Packet {
    struct Radiotap radiotap;
    struct Dot11_Frame deauth;
    struct Fixed_Parameter fixed;
    struct Taggd_Parameter taged;
    uint8_t channel_switch_announcement[5];
};
#pragma pack(pop)