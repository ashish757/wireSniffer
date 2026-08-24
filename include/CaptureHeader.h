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
    std::vector<uint8_t> rawData;
    std::string payload;
};


extern std::vector<CapturedPacket> g_livePacketList;
extern std::vector<CapturedPacket> g_filePacketList;

extern std::mutex g_packetMutex;
extern bool g_isCapturing;

void packetHandler(u_char *userDta, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void CaptureThreadFunc();
void saveCaptureToFile(const std::string& fileName);
bool loadCaptureFromFile(const std:: string& filename);






#endif

