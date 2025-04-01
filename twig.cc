#include <iostream>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "twig.h"

using namespace std;

int DEBUG = 0;
int fd = -1;
bool flipValues = false;

void cliHelp(string cmd);

void readPCap();

bool readPacket();

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

    while (true){
        bool readPacketSuccess = readPacket();
        if (!readPacketSuccess) {
            sleep(1);
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
        printf("\tts_secs: %x\n", packetHeader->ts_secs);
        printf("\tts_usecs: %x\n", packetHeader->ts_usecs);
        printf("\tcaplen: %x\n", packetHeader->caplen);
        printf("\tlen: %x\n", packetHeader->len);
    }

    exit(0);
}