//
// Created by Ashish Raj Singh on 21/08/26.
//

#ifndef WIRESNIFFER_CAPTUREHEADER_H
#define WIRESNIFFER_CAPTUREHEADER_H


#include <string>
#include <vector>
#include <mutex>
#include <pcap.h>
#include "ProtocolHeaders.h"



struct CapturedPacket {
    int id;
    std::string time;
    std::string source;
    std::string destination;
    std::string protocol;
    int length;
    std::string info;
};


extern std::vector<CapturedPacket> g_packetList;
extern std::mutex g_packetMutex;
extern bool g_isCapturing;

void packetHandler(u_char *userDta, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void CaptureThreadFunc();




#endif

