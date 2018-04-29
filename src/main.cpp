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
string getIP(string hostName)
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
			memcpy((char *)&(server.sin_addr), host_ent->h_addr, host_ent->h_length);
			addr.s_addr = *(u_long *)host_ent->h_addr;	//Taken from   https://msdn.microsoft.com/en-us/library/ms738524(VS.85).aspx 
			return inet_ntoa(addr);
		}
		else if (host_ent == NULL)
		{
			return "";
		}
	}
	return host;
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

int send_icmp_packet(SOCKET sock) {
	return 0;
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

	string destination_ip= argv[1];
	printf("\n%s\n", destination_ip);

	//copying the targethost. Taken from hw3.3
	char* targetHost = (char*)malloc(destination_ip.length() + 1);
	memcpy(targetHost, destination_ip.c_str(), destination_ip.length() + 1);
	targetHost[destination_ip.length()] = 0;

	string targetHostStr(targetHost);	
	string ip = getIP(targetHostStr);
	cout << ip << endl;
	
	//printf("\nIP Address is \n", ip);
	struct sockaddr_in remote;
	/*
	Creating sockaddr_in code
	*/
	

	memset(&remote, 0, sizeof(remote));
	//inet_pton(AF_INET, hostIP, &remote.sin_addr);
	//remote.sin_addr.s_addr = inet_addr(hostIP);
	//remote.sin_port = htons(magic_port);   //important. Server s3.irl.tamu.edu running on Windows. No need to send htons()
	remote.sin_family = AF_INET;

	
	// buffer for the ICMP header
	u_char send_buf [MAX_ICMP_SIZE]; /* IP header is not present here */

	ICMPHeader *icmp = (ICMPHeader *)send_buf;

	// set up the echo request
	// no need to flip the byte order
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;

	// set up ID/SEQ fields as needed todo
	icmp->id = (u_short)GetCurrentProcessId();
	// initialize checksum to zero
	icmp->checksum = 0;

	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes
	icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);


	// set proper TTL
	int ttl = 1; //set the ttl as required

	//href :// taken from previous HWs
	
	/* ready to create a socket */
	SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}


	// need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
	// name in multicast headers – do not use it!


	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
		printf("Setsocket failed with %d \n",WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	//use regular sendto on the above packet
	int sendtostatus = sendto(sock, (const char*)icmp, sizeof(ICMPHeader), 0, (struct sockaddr*)&remote, sizeof(remote));
	
	printf("Sendto Status %d", sendtostatus);

	u_char rec_buf[MAX_REPLY_SIZE];  /* this buffer starts with an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	
	
	// receive from the socket into rec_buf

	//todo


	// check if this is TTL_expired; make sure packet size >= 56 bytes


	if (router_icmp_hdr->type == (u_char)11 && router_icmp_hdr->code == (u_char)0)
	{
		if (orig_ip_hdr->proto == (u_char)1 )
		{
			// check if process ID matches
			if (orig_icmp_hdr->id == GetCurrentProcessId())
			{
				printf("Yes here");
				// take router_ip_hdr->source_ip and
				// initiate a DNS lookup
			}
		}
	}


}

