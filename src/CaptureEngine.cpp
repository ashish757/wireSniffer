#include "../include/CaptureHeader.h"
#include <iostream>
#include <arpa/inet.h>

std::vector<CapturedPacket> g_packetList;
std::mutex g_packetMutex;
bool g_isCapturing = true;

int g_packetCount = 1;

void packetHandler(u_char *userDta, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t eth_type = ntohs(eth->type);

    CapturedPacket newPacket;
    newPacket.id = g_packetCount++;
    newPacket.time = "Live";
    newPacket.length = pkthdr->len;

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    newPacket.source = macStr;

    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
        eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
    newPacket.destination = macStr;

    if (eth_type == 0x0800) {
        newPacket.protocol = "IPv4";
        const IPv4Header* ip  = reinterpret_cast<const IPv4Header*>(packet + sizeof(EthernetHeader));
        char ipStr[INET_ADDRSTRLEN];
        
        inet_ntop(AF_INET, &(ip->src_ip), ipStr, INET_ADDRSTRLEN);
        newPacket.source = ipStr;
        
        inet_ntop(AF_INET, &(ip->dest_ip), ipStr, INET_ADDRSTRLEN);
        newPacket.destination = ipStr;

        int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

        if (ip->protocol == 6) {
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(packet + sizeof(EthernetHeader) + ip_header_len);
            uint16_t src_port = ntohs(tcp->src_port);
            uint16_t dest_port = ntohs(tcp->dest_port);

            bool is_syn = (tcp->flags & 0x02) != 0;
            bool is_ack = (tcp->flags & 0x10) != 0;

            char infoStr[64];
            snprintf(infoStr, sizeof(infoStr), "TCP %d > %d [%s%s]",
                src_port, dest_port, is_syn ? "SYN " : "", is_ack ? "ACK " : ""
            );
            newPacket.info = infoStr;
        }
        else if (ip->protocol == 17) {
            const UDPHeader* udo = reinterpret_cast<const UDPHeader*>(packet + sizeof(EthernetHeader) + ip_header_len);
            uint16_t src_port = ntohs(udo->src_port);
            uint16_t dest_port = ntohs(udo->dest_port);

            char infoStr[64];
            snprintf(infoStr, sizeof(infoStr), "UDP %d > %d", src_port, dest_port);
            newPacket.info = infoStr;
        }
        else if (ip->protocol == 1) newPacket.info = "ICMP (Ping)";
        else newPacket.info = "Unknown IP Payload";

    } else if (eth_type == 0x0806) {
        newPacket.protocol = "ARP";
        newPacket.info = "Address Resolution Protocol";
    } else {
        newPacket.protocol = "ETH";
        newPacket.info = "Unknown / Non-IPv4 Frame";
    }

    newPacket.rawData.assign(packet, packet + pkthdr->caplen);

    std::lock_guard<std::mutex> lock(g_packetMutex);
    g_packetList.push_back(newPacket);
}

void CaptureThreadFunc() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", 65535, 1, 100, errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open device: " << errbuf << std::endl;
        std::cerr << "Running with sudo??" << std::endl;
        return;
    }

    while (g_isCapturing) {
        pcap_dispatch(handle, 10, packetHandler, nullptr);
    }
    pcap_close(handle);
}