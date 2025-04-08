#include <iostream>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <time.h>
#include <vector>
#include "twig.h"

using namespace std;

int DEBUG = 0;
int fd = -1;
int outputFd = -1;
bool flipValues = false;

void cliHelp(string cmd);

void readPCap();// Calls readPacket() on infinite loop

bool readPacket();// Calls readEthernet()

bool readEthernet(pcap_pkthdr* packetHeader);// Calls processIpv4() or processArp()

bool processIpv4(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, char ipBuffer[], int bufferLen);// Calls processIcmp() or processUdp()

bool processIcmp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, 
                ipv4_hdr* ipHeader, char icmpBuffer[], int bufferLen);// Calls createEchoReply()

bool processUdp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader,
                ipv4_hdr* ipHeader, char udpBuffer[], int bufferLen);

bool processArp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, char arpBuffer[], int bufferLen);

void createIcmpEchoReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, 
                        icmp_hdr* icmpHeader, char icmpBuffer[], int bufferLen);

void createUdpEchoReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader,
                        udp_hdr* udpHeader, char udpBuffer[], int bufferLen);

void createUdpTimeReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader,
                        udp_hdr* udpHeader, char udpBuffer[], int bufferLen);

void createEchoReplyHeaders(iovec iov[], pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader);

uint16_t generateIcmpChecksum(icmp_hdr* icmpHeader, char dataBuffer[], int bufferLen);

uint16_t generateUdpChecksum(ipv4_hdr* ipHeader, udp_hdr* udpHeader, char dataBuffer[], int bufferLen);

uint16_t onesCompSum(vector<uint16_t> values);

int main(int argc, char *argv[]){
    string ipAddr = "";
    string fileName;

    for (int i = 1; i < argc; i ++){
        if (strcmp(argv[i], "-d") == 0){
            DEBUG ++;
        }
        else if (strcmp(argv[i], "-i") == 0){
            if (i == argc-1){
                cliHelp(argv[0]);
            }
            ipAddr = argv[i+1];
            i++;
        }
        else {
            cliHelp(argv[0]);
        }
    }
    if (ipAddr == ""){
        cliHelp(argv[0]);
    }

    if (DEBUG){
        cout << "Beginning twig on IPv4 Address " << ipAddr << "\n";
    }

    fileName = ipAddr + ".dmp";
    fd = open(fileName.c_str(), O_RDWR);
    if (fd == -1){
        cerr << "Error opening " << fileName << "\n";
        exit(0);
    }
    if (DEBUG){
        cout << "Opened " << fileName << "\n";
    }

    outputFd = open(fileName.c_str(), O_WRONLY | O_APPEND);
    if (outputFd == -1){
        fflush(stdout);
        fprintf(stderr, "Error opening test-output.dmp\n");
        exit(0);
    }
    if (DEBUG){
        printf("Opened test-output.dmp at %u\n", outputFd);
    }

    readPCap();
}

void cliHelp(string cmd){
    cout << "Usage: " << cmd << " [-d] -i IPv4addr_masklength\n";
    exit(0);
}

void readPCap(){
    if (DEBUG > 1){
        cout << "Entering Packet Capture\n";
    }

    struct pcap_file_header* pcapFileHeader = new pcap_file_header;
    while (true){
        int readSuccess = read(fd, pcapFileHeader, sizeof(struct pcap_file_header));
        if (readSuccess == sizeof(struct pcap_file_header)){
            break;
        }
        sleep(1);
    }

	if (pcapFileHeader->magic != PCAP_MAGIC){
		if (ntohl(pcapFileHeader->magic) != PCAP_MAGIC){
			fflush(stdout);
			fprintf(stderr, "invalid magic number: 0x%08x\n", pcapFileHeader->magic);
			exit(0);
		}
		pcapFileHeader->magic = ntohl(pcapFileHeader->magic);
		pcapFileHeader->version_major = ntohs(pcapFileHeader->version_major);
		pcapFileHeader->version_minor = ntohs(pcapFileHeader->version_minor);
		pcapFileHeader->linktype = ntohl(pcapFileHeader->linktype);
		pcapFileHeader->sigfigs = ntohl(pcapFileHeader->sigfigs);
		pcapFileHeader->snaplen = ntohl(pcapFileHeader->snaplen);
		pcapFileHeader->thiszone = ntohl(pcapFileHeader->thiszone);
		flipValues = true;
	}

	if (pcapFileHeader->version_major != PCAP_VERSION_MAJOR || pcapFileHeader->version_minor != PCAP_VERSION_MINOR){
		fflush(stdout);
		fprintf(stderr, "invalid pcap version: %u.%u\n", pcapFileHeader->version_major, pcapFileHeader->version_minor);
		exit(0);
	}

    if (DEBUG){
        printf("PCap Header read successfully\n");
    }
    if (DEBUG > 1){
        printf("\tMagic: %x\n", pcapFileHeader->magic);
    }

    int packetCount = 0;
    while (true){
        bool readPacketSuccess = readPacket();
        if (!readPacketSuccess) {
            sleep(1);
        }
        else {
            if (DEBUG){
                printf("Packet %d read finished successful\n\n", packetCount);
            }
            packetCount ++;
        }
    }
}

bool readPacket(){
    char packetHeaderBuf[10000];
    struct pcap_pkthdr* packetHeader;

    int readSuccess = read(fd, packetHeaderBuf, sizeof(struct pcap_pkthdr));
    if (readSuccess != sizeof(struct pcap_pkthdr)){
        return false;
    }
    packetHeader = (struct pcap_pkthdr*)(packetHeaderBuf);

    if (flipValues){
        packetHeader->ts_secs = ntohl(packetHeader->ts_secs);
        packetHeader->ts_usecs = ntohl(packetHeader->ts_usecs);
        packetHeader->caplen = ntohl(packetHeader->caplen);
        packetHeader->len = ntohl(packetHeader->len);
    }

    if (DEBUG){
        printf("Packet read successful\n");
    }
    if (DEBUG > 1){
        printf("\tts_secs: %u\n", packetHeader->ts_secs);
        printf("\tts_usecs: %u\n", packetHeader->ts_usecs);
        printf("\tcaplen: %u\n", packetHeader->caplen);
        printf("\tlen: %u\n", packetHeader->len);
    }
    if (DEBUG > 2){
        printf("\tPacket header hex: ");
        printf("%08x %08x %08x %08x\n", packetHeader->ts_secs, packetHeader->ts_usecs, packetHeader->caplen, packetHeader->len);
    }

    return readEthernet(packetHeader);
}

bool readEthernet(pcap_pkthdr* packetHeader){
    const int maxPacketSize = 15000;
    char ethBuffer[maxPacketSize];
    struct eth_hdr *ethHeader;
    if (DEBUG){
        printf("Reading ethernet packet of length %d\n", packetHeader->caplen);
    }
    
    bpf_u_int32 useCaplen = packetHeader->caplen;

    if (useCaplen > maxPacketSize){
        fflush(stdout);
        fprintf(stderr, "packet larger than accepted length\n");
        exit(0);
    }

    bpf_u_int32 readSuccess = read(fd, ethBuffer, useCaplen);
    if (readSuccess == useCaplen){
        ethHeader = (struct eth_hdr*)(ethBuffer);
    }
    else {
        return false;
    }

    if (DEBUG){
        printf("Read ethernet header successful\n");
    }
    if (DEBUG > 2){
        printf("\tEthernet header hex: ");
        for (int i = 0; i < 6; i ++){
            printf("%02x ", ethHeader->dest_addr[i]);
        }
        for (int i = 0; i < 6; i ++){
            printf("%02x ", ethHeader->src_addr[i]);
        }
        printf("%04x\n", ethHeader->ether_type);
    }

    if (ntohs(ethHeader->ether_type) == IP_ETHER_TYPE){
        return processIpv4(packetHeader, ethHeader, ethBuffer+sizeof(struct eth_hdr), useCaplen-sizeof(struct eth_hdr));
    }
    else if (ntohs(ethHeader->ether_type) == ARP_ETHER_TYPE){
        return processArp(packetHeader, ethHeader, ethBuffer + sizeof(struct eth_hdr), useCaplen-sizeof(struct eth_hdr));
    }

    return true;
}

bool processIpv4(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, char ipBuffer[], int bufferLen){
    struct ipv4_hdr* ipHeader = (struct ipv4_hdr*)(ipBuffer);


    if (DEBUG){
        printf("Read ipv4 header successful\n");
    }

    if (ipHeader->proto == ICMP_PROTO){
        return processIcmp(packetHeader,ethHeader,ipHeader, ipBuffer + sizeof(struct ipv4_hdr), bufferLen-sizeof(struct ipv4_hdr));
    }
    if (ipHeader->proto == UDP_PROTO){
        return processUdp(packetHeader, ethHeader, ipHeader, ipBuffer + sizeof(struct ipv4_hdr), bufferLen-sizeof(struct ipv4_hdr));
    }

    return true;
}

bool processIcmp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, char icmpBuffer[], int bufferLen){
    struct icmp_hdr* icmpHeader = (struct icmp_hdr*)(icmpBuffer);

    if (DEBUG){
        printf("Read icmp header successful\n");
    }
    if (DEBUG > 1){
        printf("\tType: %d\n", icmpHeader->type);
        printf("\tCode: %d\n", icmpHeader->code);
        printf("\tChecksum: 0x%x\n", icmpHeader->checksum);
        printf("\tContent: 0x%x\n", icmpHeader->content);
    }

    if (icmpHeader->type == ICMP_ECHO_REQ_TYPE){
        if (DEBUG){
            printf("Replying to echo request\n");
        }
        createIcmpEchoReply(packetHeader, ethHeader, ipHeader, icmpHeader, icmpBuffer, bufferLen);
    }

    return true;
}

bool processArp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, char arpBuffer[], int bufferLen){
    // struct arp_hdr* arpHeader = (struct arp_hdr*)(ethBuffer);

    if (DEBUG){
        printf("Read arp header successful\n");
    }

    return true;
}

void createIcmpEchoReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, icmp_hdr* icmpHeader, char icmpBuffer[], int bufferLen){
    struct iovec iov[5];
    createEchoReplyHeaders(iov, packetHeader, ethHeader, ipHeader);
    icmp_hdr* replyIcmpHeader = new icmp_hdr;

    *replyIcmpHeader = *icmpHeader;
    replyIcmpHeader->type = ICMP_ECHO_REPLY_TYPE;
    replyIcmpHeader->checksum = generateIcmpChecksum(replyIcmpHeader, icmpBuffer, bufferLen);
    iov[3].iov_base = replyIcmpHeader;
    iov[3].iov_len = sizeof(struct icmp_hdr);

    iov[4].iov_base = icmpBuffer + sizeof(struct icmp_hdr);
    iov[4].iov_len = packetHeader->caplen - sizeof(struct eth_hdr) - sizeof(struct ipv4_hdr) - sizeof(struct icmp_hdr);

    int writeSuccess = writev(outputFd, iov, 5);
    if (writeSuccess == -1){
        fflush(stdout);
        perror("ICMP Echo reply failed");
        exit(0);
    }
    if (DEBUG){
        printf("ICMP Echo reply successful. %d bytes written\n", writeSuccess);
    }
}

uint16_t generateIcmpChecksum(icmp_hdr* icmpHeader, char dataBuffer[], int bufferLen){
    uint32_t checksum = 0;
    checksum += (icmpHeader->type << 8) + (icmpHeader->code);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += htons(icmpHeader->content) & 0xFFFF;
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += htons(icmpHeader->content >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);


    for (int i = sizeof(struct icmp_hdr); i < bufferLen; i += 2){
        uint16_t group = ((*(dataBuffer + i) & 0xFF) << 8) + (*(dataBuffer + i + 1) & 0xFF);
        checksum += group;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    if (DEBUG){
        printf("Generating checksum %04x\n", htons(~checksum));
    }

    return htons(~checksum);
}

bool processUdp(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, char udpBuffer[], int bufferLen){
    struct udp_hdr* udpHeader = (struct udp_hdr*)(udpBuffer);

    if (DEBUG){
        printf("Reading UDP Header\n");
    }
    if (DEBUG > 1){
        printf("\tSource port: %x\n", ntohs(udpHeader->src_port));
        printf("\tDest port: %x\n", ntohs(udpHeader->dest_port));
    }

    if (ntohs(udpHeader->dest_port) == UDP_ECHO_REQ_PORT){
        createUdpEchoReply(packetHeader, ethHeader, ipHeader, udpHeader, udpBuffer, bufferLen);
    }
    if (ntohs(udpHeader->dest_port) == UDP_TIME_REQ_PORT){
        createUdpTimeReply(packetHeader, ethHeader, ipHeader, udpHeader, udpBuffer, bufferLen);
    }

    return true;
}

void createUdpEchoReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, udp_hdr* udpHeader, char udpBuffer[], int bufferLen){
    if (DEBUG){
        printf("Create UDP Echo reply\n");
    }

    struct iovec iov[5];
    createEchoReplyHeaders(iov, packetHeader, ethHeader, ipHeader);
    struct udp_hdr* replyUdpHeader = new udp_hdr;

    struct ipv4_hdr* replyIpHeader = (struct ipv4_hdr*)(iov[2].iov_base);

    replyUdpHeader->dest_port = udpHeader->src_port;
    replyUdpHeader->src_port = udpHeader->dest_port;
    replyUdpHeader->length = udpHeader->length;
    replyUdpHeader->csum = generateUdpChecksum(replyIpHeader, replyUdpHeader, udpBuffer+sizeof(struct udp_hdr), bufferLen-sizeof(struct udp_hdr));
    iov[3].iov_base = replyUdpHeader;
    iov[3].iov_len = sizeof(struct udp_hdr);

    iov[4].iov_base = udpBuffer + sizeof(struct udp_hdr);
    iov[4].iov_len = bufferLen-sizeof(struct udp_hdr);

    int writeSuccess = writev(outputFd, iov, 5);
    if (writeSuccess == -1){
        fflush(stdout);
        perror("UDP Echo reply failed");
        exit(0);
    }
    if (DEBUG){
        printf("UDP Echo reply successful\n");
    }
}

void createUdpTimeReply(pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader, udp_hdr* udpHeader, char udpBuffer[], int bufferLen){
    if (DEBUG){
        printf("Creating UDP Time Protocol response\n");
    }

    struct iovec iov[5];
    
    struct pcap_pkthdr* replyPacketHeader = new pcap_pkthdr;
    struct eth_hdr* replyEthHeader = new eth_hdr;
    struct ipv4_hdr* replyIpHeader = new ipv4_hdr;
    struct udp_hdr* replyUdpHeader = new udp_hdr;

    *replyPacketHeader = *packetHeader;
    replyPacketHeader->caplen = sizeof(struct eth_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + 4;
    replyPacketHeader->len = replyPacketHeader->caplen;
    iov[0].iov_base = replyPacketHeader;
    iov[0].iov_len = sizeof(struct pcap_pkthdr);

    memcpy(replyEthHeader->dest_addr, ethHeader->src_addr, 6);
    memcpy(replyEthHeader->src_addr, ethHeader->dest_addr, 6);
    replyEthHeader->ether_type = ethHeader->ether_type;
    iov[1].iov_base = replyEthHeader;
    iov[1].iov_len = sizeof(struct eth_hdr);

    memcpy(replyIpHeader, ipHeader, sizeof(struct ipv4_hdr));
    replyIpHeader->dest_addr = ipHeader->source_addr;
    replyIpHeader->source_addr = ipHeader->dest_addr;
    replyIpHeader->total_length = htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) + 4);
    iov[2].iov_base = replyIpHeader;
    iov[2].iov_len = sizeof(struct ipv4_hdr);

    uint32_t replyTime = time(NULL) + 2208988800;// Seconds from midnight 1900 to midnight 1970, RFC 868
    char timeBuf[4];
    for (int i = 0; i < 4; i ++){
        timeBuf[3-i] = (char)(((replyTime) >> 8*i) & 0xFF);
    }
    if (DEBUG > 1){
        printf("Time since 1900 generated: %u seconds\n", replyTime);
    }
    if (DEBUG > 2){
        printf("\t%u %u %u %u\n", timeBuf[0], timeBuf[1], timeBuf[2], timeBuf[3]);
        printf("\t%x => %02x %02x %02x %02x\n", htonl(replyTime), timeBuf[0], timeBuf[1], timeBuf[2], timeBuf[3]);
    }
    iov[4].iov_base = timeBuf;
    iov[4].iov_len = 4;

    replyUdpHeader->dest_port = udpHeader->src_port;
    replyUdpHeader->src_port = udpHeader->dest_port;
    replyUdpHeader->length = htons(sizeof(struct udp_hdr) + 4);
    replyUdpHeader->csum = htons(generateUdpChecksum(replyIpHeader, replyUdpHeader, timeBuf, 4));
    iov[3].iov_base = replyUdpHeader;
    iov[3].iov_len = sizeof(struct udp_hdr);


    int writeSuccess = writev(outputFd, iov, 5);
    if (writeSuccess == -1){
        fflush(stdout);
        perror("Error writing udp time reply");
        exit(0);
    }
    if (DEBUG){
        printf("UDP Time Protocol response written succesfully\n");
    }
}

uint16_t generateUdpChecksum(ipv4_hdr* ipHeader, udp_hdr* udpHeader, char dataBuffer[], int bufferLen){
    vector<uint16_t> values;
    values.push_back( htons(ipHeader->source_addr & 0xFFFF));
    values.push_back(htons(ipHeader->source_addr >> 16));
    values.push_back(htons(ipHeader->dest_addr & 0xFFFF));
    values.push_back(htons(ipHeader->dest_addr >> 16));
    values.push_back((ipHeader->proto & 0xFF));
    values.push_back(htons(udpHeader->src_port));
    values.push_back(htons(udpHeader->dest_port));
    values.push_back(htons(udpHeader->length));
    values.push_back(htons(udpHeader->length));
    for (int i = 0; i < bufferLen; i += 2){
        values.push_back(((*(dataBuffer + i) & 0xFF) << 8) + (*(dataBuffer + i + 1) & 0xFF));
    }
    
    return onesCompSum(values);
}

void createEchoReplyHeaders(iovec iov[], pcap_pkthdr* packetHeader, eth_hdr* ethHeader, ipv4_hdr* ipHeader){
    pcap_pkthdr* replyPacketHeader = new pcap_pkthdr;
    eth_hdr* replyEthHeader = new eth_hdr;
    ipv4_hdr* replyIpHeader = new ipv4_hdr;

    *replyPacketHeader = *packetHeader;
    iov[0].iov_base = replyPacketHeader;
    iov[0].iov_len = sizeof(struct pcap_pkthdr);

    memcpy(replyEthHeader->dest_addr, ethHeader->src_addr, 6);
    memcpy(replyEthHeader->src_addr, ethHeader->dest_addr, 6);
    replyEthHeader->ether_type = ethHeader->ether_type;
    iov[1].iov_base = replyEthHeader;
    iov[1].iov_len = sizeof(struct eth_hdr);

    *replyIpHeader = *ipHeader;
    replyIpHeader->dest_addr = ipHeader->source_addr;
    replyIpHeader->source_addr = ipHeader->dest_addr;
    iov[2].iov_base = replyIpHeader;
    iov[2].iov_len = sizeof(struct ipv4_hdr);
}


uint16_t onesCompSum(vector<uint16_t> values){
    if (DEBUG > 2){
        printf("One's complement summing:\n");
    }
    uint32_t sum = 0;
    for (size_t i = 0; i < values.size(); i ++){
        sum += values[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
        if (DEBUG > 2){
            printf("\t%04x\n", values[i]);
        }
    }

    if (DEBUG > 1){
        printf("One's complement sum found: %04x\n", (~sum) & 0xFFFF);
    }

    return (~sum) & 0xFFFF;
}
