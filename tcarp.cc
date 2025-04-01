/**
 * File completed by Noah Fox for CS 4440
 */

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include "tcarp.h"



int debug=0;

void print_ethernet(struct eth_hdr *peh) {
	for (int i = 0; i < 6; i ++){
		printf("%02x", peh->dest_addr[i]);
		if (i < 5){
			printf(":");
		}
	}
	printf("	");
	for (int i = 0; i < 6; i ++){
		printf("%02x", peh->src_addr[i]);
		if (i < 5){
			printf(":");
		}
	}
	printf("	");
	printf("0x%04x\n", ntohs(peh->ether_type));
}

void print_decimal_dot(uint32_t addr){
	for (int i = 24; i >= 0; i -= 8){
		printf("%d", (addr & (0xff << i)) >> i);
		if (i != 0){
			printf(".");
		}
	}
}

void print_tcp(char tcpBuffer[]){
	struct tcp_hdr *tcphdr;
	tcphdr = (struct tcp_hdr *)(tcpBuffer);

	printf("\tTCP:\tSport:\t%d\n", ntohs(tcphdr->src_port));
	printf("\t\tDport:\t%d\n", ntohs(tcphdr->dest_port));

	char flagChars[] = "FSRPAU";
	printf("\t\tFlags:\t");
	for (int i = 0; i < 6; i ++){
		printf("%c", ((tcphdr->code_bits) & (1 << i)) ? flagChars[i] : '-');
	}
	printf("\n");

	printf("\t\tSeq:\t%u\n", ntohl(tcphdr->seq_num));
	printf("\t\tACK:\t%u\n", ntohl(tcphdr->ack_num));
	printf("\t\tWin:\t%d\n", ntohs(tcphdr->window));
	printf("\t\tCSum:\t%d", ntohs(tcphdr->csum));
}

void print_udp(char udpBuffer[]){
	struct udp_hdr *udphdr;
	udphdr = (struct udp_hdr *)(udpBuffer);

	printf("\tUDP:\tSport:\t%d\n", ntohs(udphdr->src_port));
	printf("\t\tDport:\t%d\n", ntohs(udphdr->dest_port));
	printf("\t\tDGlen:\t%d\n", ntohs(udphdr->length));
	printf("\t\tCSum:\t%d", ntohs(udphdr->csum));
}

void print_ip(char ipBuffer[]){
	struct ipv4_hdr *iphdr;
	iphdr = (struct ipv4_hdr *)(ipBuffer);
	printf("\tIP:\tVers:\t%d\n", iphdr->vers);
	printf("\t\tHlen:\t%d bytes\n", 4*(iphdr->hlen));
	printf("\t\tSrc:\t");
	print_decimal_dot(ntohl(iphdr->source_addr));
	printf("\t\n");
	printf("\t\tDest:\t");
	print_decimal_dot(ntohl(iphdr->dest_addr));
	printf("\t\n");

	printf("\t\tTTL:\t%d\n", iphdr->time);
	printf("\t\tFrag Ident:\t%d\n", ntohs(iphdr->ident));
	printf("\t\tFrag Offset:\t%d\n", (ntohs(iphdr->frag) & 0x1fff) * 8);
	printf("\t\tFrag DF:\t%s\n", (ntohs(iphdr->frag) & (1 << 14)) ? "yes" : "no");
	printf("\t\tFrag MF:\t%s\n", (ntohs(iphdr->frag) & (1 << 13)) ? "yes" : "no");
	printf("\t\tIP CSum:\t%d\n", ntohs(iphdr->check_sum));
	printf("\t\tType:\t0x%x\t", iphdr->proto);


	if (iphdr->proto == TCP_PROTO){
		printf("(TCP)\n");
		print_tcp(ipBuffer + sizeof(struct ipv4_hdr));
	}
	else if (iphdr->proto == UDP_PROTO){
		printf("(UDP)\n");
		print_udp(ipBuffer + sizeof(struct ipv4_hdr));
	}
	printf("\n");
}

void print_arp(char arpBuffer[]){
	struct arp_hdr *arphdr;
	arphdr = (struct arp_hdr *)(arpBuffer);

	printf("\tARP:\tHWtype:\t%d\n", ntohs(arphdr->hardware_type));
	printf("\t\thlen:\t%d\n", arphdr->hlen);
	printf("\t\tplen:\t%d\n", arphdr->plen);
	printf("\t\tOP:\t%d (%s)\n", ntohs(arphdr->operation), (ntohs(arphdr->operation) == 1) ? "ARP request" : "ARP reply");
	printf("\t\tHardware:\t");
	for (int i = 0; i < 6; i ++){
		printf("%02x%s", arphdr->src_haddr[i], (i == 5) ? "" : ":");
	}
	printf("\n\t\t\t==>\t");
	for (int i = 0; i < 6; i ++){
		printf("%02x%s", arphdr->dest_haddr[i], (i == 5) ? "" : ":");
	}
	printf("\n");

	printf("\t\tProtocol:\t");
	for (int i = 0; i < 4; i ++){
		printf("%d%s", arphdr->src_iaddr[i], (i == 3) ? "" : ".");
	}
	printf("\t\n\t\t\t==>\t");
	for (int i = 0; i < 4; i ++){
		printf("%d%s", arphdr->dest_iaddr[i], (i == 3) ? "" : ".");
	}
	printf("\t\n");
}

/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

int main(int argc, char *argv[])
{
	struct pcap_file_header pfh;
	char *filename;

	/* start with something like this (or use this if you like it) */
	if (argc == 3) {
		filename = argv[2];
	} else if ((argc == 4) && (strcmp(argv[1],"-d") == 0)) {
		debug = 1;
		filename = argv[3];
	} else {
		fprintf(stdout,"Usage: %s [-d] -n filename\n", argv[0]);
		exit(99);
	}

	if (debug) printf("Trying to read from file '%s'\n", filename);

	/* now open the file (or if the filename is "-" make it read from standard input)*/
	std::istream* in;
	if (strcmp(filename, "-")){
		std::ifstream* fh = new std::ifstream();
		fh->open(filename, std::fstream::in | std::fstream::binary);
		if (fh->fail()){
			fflush(stdout);
			fprintf(stderr, "%s: Permission denied\n", filename);
			exit(0);
		}
		in = fh;
	}
	else {
		in = &std::cin;
	}

	if (!(in->read((char *)&pfh, sizeof(pfh)))){
		std::streamsize len = in->gcount();
		fflush(stdout);
		fprintf(stderr,"truncated pcap header: only %ld bytes\n", len);
		exit(0);
	}

	bool flipValues = false;
	if (pfh.magic != PCAP_MAGIC){
		if (ntohl(pfh.magic) != PCAP_MAGIC){
			fflush(stdout);
			fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
			exit(0);
		}
		pfh.magic = ntohl(pfh.magic);
		pfh.version_major = ntohs(pfh.version_major);
		pfh.version_minor = ntohs(pfh.version_minor);
		pfh.linktype = ntohl(pfh.linktype);
		pfh.sigfigs = ntohl(pfh.sigfigs);
		pfh.snaplen = ntohl(pfh.snaplen);
		pfh.thiszone = ntohl(pfh.thiszone);
		flipValues = true;
	}

	if (pfh.version_major != PCAP_VERSION_MAJOR || pfh.version_minor != PCAP_VERSION_MINOR){
		fflush(stdout);
		fprintf(stderr, "invalid pcap version: %u.%u\n", pfh.version_major, pfh.version_minor);
		exit(0);
	}

	/* read the pcap_file_header at the beginning of the file, check it, then print as requested */
	printf("header magic: %x\n", pfh.magic);
	printf("header version: %u %u\n", pfh.version_major, pfh.version_minor);
	printf("header linktype: %u\n\n", pfh.linktype);

	/* now read each packet in the file */
	while (1) {
		char packet_buffer[10000];
		struct pcap_pkthdr *phdr;

		/* read the pcap_packet_header, then print as requested */
		if (in->read(packet_buffer, sizeof(struct pcap_pkthdr))){
			phdr = (struct pcap_pkthdr *)(packet_buffer);
		}
		else if (in->eof()){
			std::streamsize len = in->gcount();
			if (len > 0){
				fflush(stdout);
				fprintf(stderr, "truncated packet header: only %ld bytes\n", len);
			}
			break;
		}
		else {
			fflush(stdout);
			fprintf(stderr, "failure in packet header read\n");
			break;
		}

		if (flipValues){
			phdr->ts_secs = ntohl(phdr->ts_secs);
			phdr->ts_usecs = ntohl(phdr->ts_usecs);
			phdr->caplen = ntohl(phdr->caplen);
			phdr->len = ntohl(phdr->len);
		}

		if (debug){
			printf("Packet header:\n");
			printf("\tts_secs: %x\n", phdr->ts_secs);
			printf("\tts_usecs: %x\n", phdr->ts_usecs);
			printf("\tcaplen: %x\n", phdr->caplen);
			printf("\tlen: %x\n", phdr->len);
		}

		/* then read the packet data that goes with it into a buffer (variable size) */
		const int maxPacketSize = 15000;
		char eth_buffer[maxPacketSize];
		struct eth_hdr *ehdr;
		if (debug) printf("Reading ethernet packet of length %d\n", phdr->caplen);
		
		bpf_u_int32 useCaplen = phdr->caplen;

		if (useCaplen > maxPacketSize){
			fflush(stdout);
			fprintf(stderr, "packet larger than accepted amount: %u > %u\n", useCaplen, maxPacketSize);
			exit(0);
		}

		if (in->read(eth_buffer, useCaplen)){
			ehdr = (struct eth_hdr *)(eth_buffer);
		}
		else if (in->eof()){
			std::streamsize len = in->gcount();
			fflush(stdout);
			fprintf(stderr, "truncated packet: only %ld bytes\n", len);
			break;
		}
		else {
			fflush(stdout);
			fprintf(stderr, "failure in ethernet header read\n");
			break;
		}



		if (pfh.linktype == 1) {
			printf("%10u.%06u000	", phdr->ts_secs, phdr->ts_usecs);
			printf("%u	%u	", phdr->caplen, phdr->len);
			print_ethernet(ehdr);


			if (ntohs(ehdr->ether_type) == IP_ETHER_TYPE){
				print_ip(eth_buffer + sizeof(struct eth_hdr));
			}
			else if (ntohs(ehdr->ether_type) == ARP_ETHER_TYPE){
				print_arp(eth_buffer + sizeof(struct eth_hdr));
			}
		}
	}
}

