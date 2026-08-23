//
// Created by Ashish Raj Singh on 22/08/26.
//

#ifndef WIRESNIFFER_UIMANAGER_H
#define WIRESNIFFER_UIMANAGER_H
#include "CaptureHeader.h"
#include "InjectionEngine.h"
#include "cstring"

class UIManager {
public:
    void Render();

private:
    void DrawPacketList();
    void DrawDetailsPane();
    void DrawHexDumpPane();
    void DrawInjectionPane();

    int selectedPacketId = -1;
    CapturedPacket selectedPacketData;

    char targetInBuffer[16] = "";
    char routerIpBuffer[16] = "";
    char attackerMacBuffer[16] = "";

    std::string injectionStatus;
};

#endif //WIRESNIFFER_UIMANAGER_H
