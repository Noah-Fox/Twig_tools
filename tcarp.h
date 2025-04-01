#ifndef TCARP_H
#define TCARP_H

#include <netinet/in.h>

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

/* every pcap file starts with this structure */
struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

#define PCAP_MAGIC         0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

const uint16_t IP_ETHER_TYPE = 0x0800;
const uint16_t ARP_ETHER_TYPE = 0x0806;
const uint8_t TCP_PROTO = 0x6;
const uint8_t UDP_PROTO = 0x11;

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */
struct pcap_pkthdr {
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

struct eth_hdr {
    uint8_t dest_addr[6];
	uint8_t src_addr[6];
	uint16_t ether_type;
};

struct ipv4_hdr {
	u_char hlen:4;
	u_char vers:4;
	uint8_t type_serv;
	uint16_t total_length;
	uint16_t ident;
	uint16_t frag;// needs parsed
	uint8_t time;
	uint8_t proto;
	uint16_t check_sum;
	uint32_t source_addr;
	uint32_t dest_addr;
};

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t hlen_res;
	uint8_t code_bits;
	uint16_t window;
	uint16_t csum;
	uint16_t urg_ptr;
};

struct udp_hdr {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t csum;
};

struct arp_hdr {
	uint16_t hardware_type;
	uint16_t proto_type;
	uint8_t hlen;
	uint8_t plen;
	uint16_t operation;
	uint8_t src_haddr[6];
	uint8_t src_iaddr[4];
	uint8_t dest_haddr[6];
	uint8_t dest_iaddr[4];
};



#endif
