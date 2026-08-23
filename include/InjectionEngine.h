//
// Created by Ashish Raj Singh on 23/08/26.
//

#ifndef WIRESNIFFER_INJECTIONENGINE_H
#define WIRESNIFFER_INJECTIONENGINE_H

#include "ProtocolHeaders.h"
#include <array>
#include <cstdint>

using ARPFrame = std::array<uint8_t, sizeof(EthernetHeader) + sizeof(ARPHeader)>;

ARPFrame buildFrame(const EthernetHeader& ethernet, const ARPHeader& arp);
void printHex(const ARPFrame& frame);


#endif //WIRESNIFFER_INJECTIONENGINE_H