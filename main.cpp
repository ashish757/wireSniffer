#include <iostream>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return 1;
    }

    if (alldevs == nullptr) {
        std::cerr << "No devices found. Did you run with Administrator/Root privileges?" << std::endl;
        return 1;
    }

    std::cout << "Available network devices:" << std::endl;

    int count = 0;
    for (device = alldevs; device != nullptr; device = device->next) {
        std::cout << ++count << ". " << device->name;
        if (device->description) {
            std::cout << " (" << device->description << ")";
        } else {
            std::cout << " (No description available)";
        }
        std::cout << std::endl;
    }

    pcap_freealldevs(alldevs);

    return 0;
}