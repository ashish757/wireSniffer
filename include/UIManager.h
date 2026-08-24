//
// Created by Ashish Raj Singh on 22/08/26.
//

#ifndef WIRESNIFFER_UIMANAGER_H
#define WIRESNIFFER_UIMANAGER_H
#include "CaptureHeader.h"
#include "InjectionEngine.h"
#include "cstring"
#include <filesystem>
#include <cstring>


class UIManager {
private:
    float packetListHeight = 350.0f;
    void DrawPacketList(const std::vector<CapturedPacket>& packetList);
    void DrawDetailsPane();
    void DrawHexDumpPane();
    void DrawInjectionPane();
    void SimulateAttack();

    int selectedPacketId = -1;
    CapturedPacket selectedPacketData;

    char targetInBuffer[16] = "";
    char routerIpBuffer[16] = "";
    char attackerMacBuffer[16] = "";

    std::string injectionStatus;
    char filterBuffer[256] = "";
    int selectedFilterIndex = 0;

    char savePathBuffer[512];
    char loadPathBuffer[512];

    std::vector<CapturedPacket> threatLog;
    bool isUnderAttack = false;


public:
    UIManager() {
        std::string currentPath = std::filesystem::current_path().string();
        std::string defaultFile =  currentPath + "/session.pcap";

        std::strncpy(savePathBuffer, defaultFile.c_str(), sizeof(savePathBuffer) -1);
        savePathBuffer[sizeof(savePathBuffer) - 1] = '\0';

        std::strncpy(loadPathBuffer, defaultFile.c_str(), sizeof(loadPathBuffer) -1);
        loadPathBuffer[sizeof(loadPathBuffer) - 1] = '\0';
    }
    void Render();

};

#endif //WIRESNIFFER_UIMANAGER_H
