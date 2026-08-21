//
// Created by Ashish Raj Singh on 21/08/26.
//


#ifndef WIRESNIFFER_PROTOCOLHEADERS_H
#define WIRESNIFFER_PROTOCOLHEADERS_H

#include <cstdint>


#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct IPv4Header {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t acknowledge;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;

};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

#pragma pack(pop)



#endif

