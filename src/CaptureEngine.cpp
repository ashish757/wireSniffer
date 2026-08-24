#include "../include/CaptureHeader.h"
#include <iostream>
#include <arpa/inet.h>

std::vector<CapturedPacket> g_livePacketList;
std::vector<CapturedPacket> g_filePacketList;

std::mutex g_packetMutex;
bool g_isCapturing = true;

int g_packetCount = 1;

void packetHandler(u_char *userDta, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    auto* targetList = reinterpret_cast<std::vector<CapturedPacket>*>(userDta);

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

            int tcp_header_len = ((tcp->data_offset >> 4) & 0x0F) * 4;
            const uint8_t* tcp_payload = packet + sizeof(EthernetHeader) + ip_header_len + tcp_header_len;
            int payload_len = pkthdr->caplen - (sizeof(EthernetHeader) + ip_header_len + tcp_header_len);

            std::string http_info = "";

            if (payload_len > 4) {
                std::string payload_str(reinterpret_cast<const char*>(tcp_payload), std::min(payload_len, 200));

                if (payload_str.rfind("GET ", 0) == 0 || payload_str.rfind("POST ", 0) == 0 || payload_str.rfind("HTTP/", 0) ==0 ) {
                    size_t newline_pos = payload_str.find("\r\n");
                    if (newline_pos == std::string::npos) newline_pos = payload_str.find('\n');
                    if (newline_pos != std::string::npos) {
                        http_info = "HTTP:" + payload_str.substr(0, newline_pos);
                    } else {
                        http_info = "HTTP: Traffic";
                    }
                }

             }

            if (!http_info.empty()) {
                newPacket.protocol = "HTTP";

                newPacket.info = http_info;
            } else {
                bool is_syn = (tcp->flags & 0x02) != 0;
                bool is_ack = (tcp->flags & 0x10) != 0;

                char infoStr[64];
                snprintf(infoStr, sizeof(infoStr), "TCP %d > %d [%s%s]",
                    src_port, dest_port, is_syn ? "SYN " : "", is_ack ? "ACK " : ""
                );
                newPacket.info = infoStr;
            }



        }
        else if (ip->protocol == 17) {
            const UDPHeader* udo = reinterpret_cast<const UDPHeader*>(packet + sizeof(EthernetHeader) + ip_header_len);
            uint16_t src_port = ntohs(udo->src_port);
            uint16_t dest_port = ntohs(udo->dest_port);

            if (src_port == 53 || dest_port == 53) {
                 const uint8_t* dns_data = packet + sizeof(EthernetHeader) + ip_header_len + sizeof(UDPHeader);
                const DNSHeader* dns = reinterpret_cast<const DNSHeader*>(dns_data);

                uint16_t flags = ntohs(dns->flags);
                bool is_response = (flags & 0x8000) != 0;

                const uint8_t* query_name = dns_data + sizeof(DNSHeader);
                std::string domain = "";

                int i = 0;
                while (query_name[i] != 0 && i < 255) {
                    int len = query_name[i];
                    if ((len & 0xC0) == 0xC0) {
                        domain += "<compressed>";
                        break;
                    }
                    i++;
                    for (int j = 0; j < len; j++) {
                        domain += static_cast<char>(query_name[i+j]);
                    }
                    i += len;
                    if (query_name[i] != 0) domain += ".";
                }

                char infoStr[128];
                snprintf(infoStr, sizeof(infoStr), "UDP %s : %s", is_response ? "Response" : "Query",
                domain.empty() ? "Unknown" : domain.c_str());
                newPacket.info = infoStr;
            } else {
                char infoStr[64];
                snprintf(infoStr, sizeof(infoStr), "UDP %d > %d", src_port, dest_port);
                newPacket.info = infoStr;
            }
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
    targetList->push_back(newPacket);
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
        pcap_dispatch(handle, 10, packetHandler, reinterpret_cast<u_char*>(&g_livePacketList));
    }
    pcap_close(handle);
}

void saveCaptureToFile(const std::string& filename) {
    std::lock_guard<std::mutex> lock(g_packetMutex);

    pcap_t* dead_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead_handle) {
        std::cerr<<"could not open file to write "<<filename<<std::endl;
        return;
    }

    pcap_dumper_t* dumper = pcap_dump_open(dead_handle, filename.c_str());
    if (!dumper) {
        std::cerr<<"could not open file to write "<<filename<<std::endl;
        pcap_close(dead_handle);
        return;
    }

    struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } header;

    header.magic = 0xa1b1c2c3d4;
    header.version_major = 2;
    header.version_minor = 3;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 34234;
    header.network = 1;


    for (const auto& p: g_livePacketList) {
        struct pcap_pkthdr p_hdr;

        p_hdr.ts.tv_sec = 0;
        p_hdr.ts.tv_usec = 0;
        p_hdr.caplen = p.rawData.size();
        p_hdr.len = p.length;

       pcap_dump(reinterpret_cast<u_char*>(dumper), &p_hdr, p.rawData.data());
    }

    pcap_dump_close(dumper);
    pcap_close(dead_handle);
    std::cout<<"successfully saved capture "<<g_livePacketList.size()<<" packets to "<<filename<<std::endl;

}


bool loadCaptureFromFile(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];


    pcap_t* handle = pcap_open_offline(filename.c_str(), errbuf);

    if (handle == nullptr) {
        std::cerr<<"Error in loading  the file: "<<errbuf<<std::endl;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_packetMutex);
        g_filePacketList.clear();
        g_packetCount = 1;
    }

    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(&g_filePacketList));

    pcap_close(handle);
    std::cout<<"loaded capture from "<<filename<<std::endl;
}


