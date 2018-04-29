/*
  Name: Avinash Saxena
  UIN: 426009625
*/


/* main.cpp
 * CSCE 463 Sample Code 
 * by Dmitri Loguinov
 */
#include "common.h"
#include "stdafx.h"
#include "SenderHeaders.h"
#include <WS2tcpip.h>

//href:// Notes from classes, hw2 pdf


using namespace std;


//href:// taken from HW1 submission of my own code

vector<Ping_Results> responses(30);
vector<long> time_packets_sent(30);

sockaddr_in fetchServer(string hostName)
{
	struct sockaddr_in server;
	in_addr addr;
	char *hostAddr;
	int len = hostName.length();
	char* host = (char*)malloc((len + 1) * sizeof(char));
	strcpy(host, hostName.c_str());
	DWORD dwRetVal = inet_addr(host);
	struct hostent *host_ent = gethostbyname(host);
	if (dwRetVal == INADDR_NONE)
	{
		if (host_ent != NULL)
		{
			addr.s_addr = *(u_long *)host_ent->h_addr;	//Taken from   https://msdn.microsoft.com/en-us/library/ms738524(VS.85).aspx 
		}
		else if (host_ent == NULL)
		{
			exit(-1);
		}
		cout << inet_ntoa(addr)<<endl;
		memcpy((char*)(&server.sin_addr), host_ent->h_addr, host_ent->h_length);
	}
	else {
		server.sin_addr.S_un.S_addr = dwRetVal;
	}
	return server;
}


//href:// taken from hw4 code pdf
u_short ip_checksum(u_short *buffer, int size)
{

	u_long cksum = 0;
	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}
	if (size)
		cksum += *(u_char *)buffer;
	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);
	/* return a bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}

int send_icmp_packet(int ttl, SOCKET sock, struct sockaddr_in remote) {
	u_char send_buf[MAX_ICMP_SIZE]; /* IP header is not present here */
	ICMPHeader *icmp = (ICMPHeader *)send_buf;
	// set up the echo request
	// no need to flip the byte order
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;

	// set up ID/SEQ fields as needed todo
	icmp->id = (u_short)GetCurrentProcessId(); //id is same for all packets. This is for checking validity of the packet
	icmp->seq = ttl;
	IPHeader *ip_h = (IPHeader* )((ICMPHeader*)send_buf + 1);
	ip_h->ttl = ttl;

	// initialize checksum to zero
	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes
	icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);

	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
		printf("Setsocket failed with %d \n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
	//use regular sendto on the above packet
	printf("--> id %d, sequence %d, ttl %d\n\n", icmp->id, icmp->seq, ip_h->ttl);
	int sendtostatus = sendto(sock, (char*)send_buf, sizeof(ICMPHeader), 0, (SOCKADDR *)&remote, sizeof(remote));
	if (sendtostatus == SOCKET_ERROR) {
		printf("WSAERROR  %d \n", WSAGetLastError());
		exit(1);
	}
	return sendtostatus;
}


char* getnamefromip(char* ip) {
	//href:// msdn https://msdn.microsoft.com/en-us/library/windows/desktop/ms738532(v=vs.85).aspx
	DWORD dwRetval;
	struct sockaddr_in sock_addr;
	char hostname[NI_MAXHOST];
	char servInfo[NI_MAXSERV];
	u_short port = 22191;
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_addr(ip);
	sock_addr.sin_port = htons(port);
	dwRetval = getnameinfo((struct sockaddr *) &sock_addr,sizeof(struct sockaddr),hostname,NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
	if (dwRetval != 0) {
		return "";
	}
	else {
		return hostname;
	}
}
int receive_icmp_response(SOCKET sock) {
	
	
	u_char rec_buf[MAX_REPLY_SIZE];  /* this buffer starts gethostname an IP header */
	
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	long rto = 500000;  //starting rto is 500 ms i.e. 500000 microseconds
	fd_set fd;
	
	struct timeval timeout;
	timeout.tv_sec = (long)((double)rto/1e6);
	timeout.tv_usec = rto;
	
	
	while (true) {
		timeout.tv_sec = (long)((double)rto / 1e6);
		timeout.tv_usec = rto;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);

		int totalSizeOnSelect = select(0, &fd, NULL, NULL, &timeout);
		if (totalSizeOnSelect == SOCKET_ERROR) {
			printf("Select failed with %d \n", WSAGetLastError());
			return SOCKET_ERROR;
		}
		if (totalSizeOnSelect < 0) {
			printf("failed select with %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
		if (totalSizeOnSelect == 0) {
			printf("Total Size on select %d\n", totalSizeOnSelect);
			continue;
		}
		int recv = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);
		if (recv == SOCKET_ERROR) {
			printf("Error in receive %d \n", WSAGetLastError());
			return recv;
		}
		if (recv < 56) {
			printf("Discarding Packet as Size <56 ");
			continue;
		}
		if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == (u_char)0)
		{
			int sequence = orig_icmp_hdr->seq;   //sequence number is the ttl
												 //cout << "Sequence Received " << sequence << endl;
			if (orig_ip_hdr->proto == (u_char)1)
			{
				// check if process ID matches
				if (orig_icmp_hdr->id == GetCurrentProcessId())
				{
					u_long ip_address_of_router = router_ip_hdr->source_ip;
					sockaddr_in dns_sock;
					dns_sock.sin_addr.s_addr = ip_address_of_router;
					char* ip = inet_ntoa(dns_sock.sin_addr);
					hostent *host_name = gethostbyname(ip);
					char *host = getnamefromip(ip);
					printf("<-- sequence %d, ip_address %s, id %d  %s\n", sequence, host_name->h_name, orig_icmp_hdr->id, host);

					Ping_Results ping_result;
					ping_result.ip = host_name->h_name;
					ping_result.host_name = host;
					ping_result.ttl = sequence;  //sequence number of packet sent
					ping_result.rtt = ((double)(timeGetTime() - time_packets_sent[sequence])/(1e3));
					responses[sequence] = ping_result;
					
				}
			}
		}


	}

	
	return 1;
}
int main(int argc, char *argv[]){
		
	if (argc != 2) {
		printf("Invalid number of arguments \n");
		return 1;
	}

	WSADATA wsaData = { 0 };
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "Main:\t WSAStartup Failed " << WSAGetLastError() << endl;
		return 1;
	}

	
	
	// ********IP ADDRESS FROM HOST *****************
	string destination_ip= argv[1];

	//copying the targethost. Taken from hw3.3
	char* targetHost = (char*)malloc(destination_ip.length() + 1);
	memcpy(targetHost, destination_ip.c_str(), destination_ip.length() + 1);
	targetHost[destination_ip.length()] = 0;

	string targetHostStr(targetHost);	
	//*****************************************************

	//*********** SERVER CODE *******************

	struct sockaddr_in remote= fetchServer(targetHostStr);
	remote.sin_family = AF_INET;
	remote.sin_port = htons(7);
	
	//*************************************************************
	

	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	

	//************SEND ICMP BUFFER******************************
	//send all the icmp packets immediately (30 packets)
	for (int ttl = 0; ttl < 30; ttl++) {
			time_packets_sent[ttl] = timeGetTime();
			send_icmp_packet(ttl, sock, remote);
	}
	//int send_status=send_icmp_packet(2,sock,remote);
	receive_icmp_response(sock);

}

