//
// Created by Ashish Raj Singh on 23/08/26.
//


#include "../include/InjectionEngine.h"
#include <cstring>
#include <iostream>
#include <iomanip>


ARPFrame buildFrame(const EthernetHeader& ethernet, const ARPHeader& arp) {
    ARPFrame frame{};

    std::memcpy(frame.data(), &ethernet, sizeof(EthernetHeader));

    std::memcpy(frame.data() + sizeof(EthernetHeader), &arp, sizeof(ARPHeader));
    return frame;
}

void printHex(const ARPFrame& frame) {
    for (std::size_t i = 0; i < frame.size(); i++) {
        if (i > 0 && i % 16 == 0) {
            std::cout << "\n";
        }

        std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<int>(frame[i]);
    }

    std::cout<<std::dec<<"\n";
}