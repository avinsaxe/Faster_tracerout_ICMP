#include "common.h"
#include "stdafx.h"

#define IP_HDR_SIZE 20 /* RFC 791 */
#define ICMP_HDR_SIZE 8 /* RFC 792 */

/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE 65200

/* max size of an IP datagram */
#define MAX_ICMP_SIZE (MAX_SIZE + ICMP_HDR_SIZE)

/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)

/* ICMP packet types */
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED 11
#define ICMP_ECHO_REQUEST 8
/* remember the current packing state */
#pragma pack (push)
#pragma pack (1)


/* define the IP header (20 bytes) */
#pragma pack(push,1)
class IPHeader {
public:
	u_char h_len : 4; 
	u_char version : 4;
	u_char tos; 
	u_short len;
	u_short ident; 
	u_short flags; 
	u_char ttl; 
	u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum;
	u_long source_ip;
	u_long dest_ip;
};
#pragma pack(pop)

/* define the ICMP header (8 bytes) */
#pragma pack(push,1)
class ICMPHeader {
public:
	u_char type; 
	u_char code; 
	u_short checksum;
	u_short id; 
	u_short seq;
};
#pragma pack(pop)


class Ping_Results {
public:
	int ttl;
	char* host_name;
	char* ip;
	double rtt;
	int num_probes=0;
	uint64_t time_sent;  //microseconds
	uint64_t time_received;  //microseconds
	bool isReceived=false;
};

class Timeouts {
public:
	int index;
	long timeout;
};
/* now restore the previous packing state */
