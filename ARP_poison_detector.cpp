#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <regex>
#include <cstdlib>
#include <pcap.h>

// Function to get the ARP cache using the system command
std::string get_arp_cache() {
    std::string output;
    const char* command = (std::string("arp -a") + " 2>&1").c_str();  // Redirect errors to stdout
    FILE* fp = popen(command, "r");
    if (!fp) {
        std::cerr << "Error executing ARP command." << std::endl;
        return "";
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        output += buffer;
    }
    fclose(fp);

    return output;
}

// Function to check ARP cache for possible poisoning
void check_for_arp_poisoning() {
    std::string arp_cache = get_arp_cache();
    if (arp_cache.empty()) {
        std::cout << "Could not retrieve ARP cache." << std::endl;
        return;
    }

    std::regex pattern(R"((\d+\.\d+\.\d+\.\d+)\s+([a-f0-9:]+)\s+)");
    std::smatch matches;
    std::map<std::string, std::string> ip_mac_mapping;
    std::istringstream stream(arp_cache);

    std::string line;
    while (std::getline(stream, line)) {
        if (std::regex_search(line, matches, pattern)) {
            std::string ip = matches[1];
            std::string mac = matches[2];
            if (ip_mac_mapping.find(ip) == ip_mac_mapping.end()) {
                ip_mac_mapping[ip] = mac;
            } else {
                if (ip_mac_mapping[ip] != mac) {
                    std::cout << "WARNING: Possible ARP Poisoning detected for IP " << ip << "!" << std::endl;
                    std::cout << "  Original MAC: " << ip_mac_mapping[ip] << std::endl;
                    std::cout << "  Attacker's MAC: " << mac << std::endl;
                } else {
                    std::cout << "ARP Entry: IP " << ip << " -> MAC " << mac << std::endl;
                }
            }
        }
    }

    std::cout << "ARP cache check complete." << std::endl;
}

// Callback function to capture ARP packets
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header*) packet;
    struct arp_header *arp_header = (struct arp_header*) (packet + sizeof(struct ether_header));

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        std::cout << "Received ARP response: IP " << inet_ntoa(*(struct in_addr*)&arp_header->arp_spa) 
                  << " -> MAC: " << std::hex << (int)arp_header->arp_sha[0] << ":" 
                  << (int)arp_header->arp_sha[1] << ":"
                  << (int)arp_header->arp_sha[2] << ":"
                  << (int)arp_header->arp_sha[3] << ":"
                  << (int)arp_header->arp_sha[4] << ":"
                  << (int)arp_header->arp_sha[5] << std::dec << std::endl;
    }
}

// Function to send ARP request and verify if the IP address responds
void arp_request(const std::string &ip) {
    std::cout << "Performing ARP request to " << ip << "..." << std::endl;

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening device for packet capture: " << errbuf << std::endl;
        return;
    }

    // Send ARP request to the target IP
    struct ether_header eth_header;
    struct arp_header arp_request;

    // Fill out Ethernet and ARP header (sending ARP request)
    memset(&eth_header, 0, sizeof(struct ether_header));
    eth_header.ether_type = htons(ETHERTYPE_ARP);

    memset(&arp_request, 0, sizeof(struct arp_header));
    arp_request.arp_htype = htons(1);
    arp_request.arp_ptype = htons(ETHERTYPE_IP);
    arp_request.arp_hlen = 6;
    arp_request.arp_plen = 4;
    arp_request.arp_op = htons(ARP_REQUEST);
    // (Fill the ARP request details here as needed)

    // Capture the response packet
    pcap_loop(handle, 1, packet_handler, NULL);
    pcap_close(handle);
}

// Main function to initiate ARP poisoning detection
int main() {
    std::string ip_address;
    std::cout << "Enter the IP address to check for ARP Poisoning:";
    std::cin >> ip_address;

    check_for_arp_poisoning();

    arp_request(ip_address);

    return 0;
}
