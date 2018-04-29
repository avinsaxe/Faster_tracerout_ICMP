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
	icmp->id = (u_short)GetCurrentProcessId();
	icmp->seq = ttl;
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
	int sendtostatus = sendto(sock, (char*)send_buf, sizeof(ICMPHeader), 0, (SOCKADDR *)&remote, sizeof(remote));
	if (sendtostatus == SOCKET_ERROR) {
		printf("WSAERROR  %d \n", WSAGetLastError());
		exit(1);
	}
	return sendtostatus;
}

int receive_icmp_response(SOCKET sock) {
	
	
	u_char rec_buf[MAX_REPLY_SIZE];  /* this buffer starts gethostname an IP header */
	int recv=recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);
	if (recv == SOCKET_ERROR) {
		printf("Error in receive %d \n",WSAGetLastError());
		return recv;
	}
	cout << "RECEIVE " << recv << endl;
	
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);


	if (router_icmp_hdr->type == (u_char)11 && router_icmp_hdr->code == (u_char)0)
	{
		if (orig_ip_hdr->proto == (u_char)1)
		{
			// check if process ID matches
			if (orig_icmp_hdr->id == GetCurrentProcessId())
			{
				printf("Yes here\n");
				// take router_ip_hdr->source_ip and
				// initiate a DNS lookup
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
	

	int send_status=send_icmp_packet(2,sock,remote);
	int receive_status = receive_icmp_response(sock);
	
	

}

