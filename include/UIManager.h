//
// Created by Ashish Raj Singh on 22/08/26.
//

#ifndef WIRESNIFFER_UIMANAGER_H
#define WIRESNIFFER_UIMANAGER_H
#include "CaptureHeader.h"


class UIManager {
public:
    void Render();

private:
    void DrawPacketList();
    void DrawDetailsPane();
    void DrawHexDumpPane();

    int selectedPacketId = -1;

    CapturedPacket selectedPacketData;

};

#endif //WIRESNIFFER_UIMANAGER_H


/*


 */