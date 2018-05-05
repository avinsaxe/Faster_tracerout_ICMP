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
#include <thread>
#include <WS2tcpip.h>
#define CURRENT_TIME_H

#include <chrono>
#include <cstdint>


//href:// Notes from classes, hw2 pdf


using namespace std;


//href:// taken from HW1 submission of my own code
long rto=0;
Timeouts t;

struct timeval timeout;
int index_of_awaited_packet = 0;
vector<Ping_Results> responses(30);
//vector<long> time_packets_sent(30);
vector<Timeouts> timeouts_interval(0);  //this is a min heap
std::thread thread_updater[30];   //max 30 threads in parallel
static int thread_num = 0;
DWORD ID = GetCurrentProcessId();
SOCKET sock;
HANDLE event_icmp = WSACreateEvent();

struct GREATER {
	bool operator()(const Timeouts&a, const Timeouts&b) const
	{
		return a.timeout>b.timeout;
	}
};

//href: https://stackoverflow.com/questions/14016921/comparator-for-min-heap-in-c
Timeouts get_root_from_min_heap() {
	if (timeouts_interval.size() == 0) {
		return Timeouts();
	}
	std::pop_heap(timeouts_interval.begin(), timeouts_interval.end(), GREATER());
	Timeouts t = (timeouts_interval.back());
	timeouts_interval.pop_back();
	//printf("POPPED element %d and remaining size is %d",t.index,timeouts_interval.size());
	///(timeouts.begin(), timeouts.end(), GREATER());
	return t;
}

//works correctly
sockaddr_in fetchServer(char* host)
{
	struct sockaddr_in remote;
	memset(&remote, 0, sizeof(struct sockaddr_in));	
	in_addr addr;
	char *hostAddr;
	DWORD dwRetVal = inet_addr(host);
	if (dwRetVal == INADDR_NONE)
	{
		struct hostent *host_ent = gethostbyname(host);
		if (host_ent != NULL)
		{
			std::memcpy((char*)(&remote.sin_addr), host_ent->h_addr, host_ent->h_length);
			addr.s_addr = *(u_long *)host_ent->h_addr;	//Taken from   https://msdn.microsoft.com/en-us/library/ms738524(VS.85).aspx 
		}
		else if (host_ent == NULL)
		{
			printf("Host Ent is null. Unable to fetch server\n");
			exit(1);
		}
		//cout << inet_ntoa(addr)<<endl;
		
	}
	else {
		remote.sin_addr.S_un.S_addr = dwRetVal;
	}
	remote.sin_family = AF_INET;
	remote.sin_port = htons(80);
	return remote;
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
	//printf("TTL is ***** %d",ttl);
	u_char send_buf[MAX_ICMP_SIZE]; /* IP header is not present here */
	ICMPHeader *icmp = (ICMPHeader *)send_buf;
	// set up the echo request
	// no need to flip the byte order
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;

	// set up ID/SEQ fields as needed todo
	icmp->id = (u_short)ID; //id is same for all packets. This is for checking validity of the packet
	icmp->seq = ttl;
	icmp->checksum = 0;
	//IPHeader *ip_h = (IPHeader* )((ICMPHeader*)send_buf + 1);
	//ip_h->ttl = ttl;

	// initialize checksum to zero
	/* calculate the checksum */
	int packet_size = sizeof(ICMPHeader); // 8 bytes
	icmp->checksum = ip_checksum((u_short *)send_buf, packet_size);
	
	if (setsockopt(sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
		printf("Setsocket failed with %d \n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//use regular sendto on the above packet
	int sendtostatus = sendto(sock, (char*)send_buf, sizeof(ICMPHeader), 0, (SOCKADDR *)&remote, sizeof(remote));
	if (sendtostatus == SOCKET_ERROR) {
		printf("WSAERROR  %d \n", WSAGetLastError());
		return 1;
	}
	printf("--> sequence %d, id %d,  ttl %d and status %d\n", icmp->seq,icmp->id, ttl,sendtostatus);
	return sendtostatus;
}



char* getnamefromip(char* ip) {
	//href:// msdn https://msdn.microsoft.com/en-us/library/windows/desktop/ms738532(v=vs.85).aspx
	DWORD dwRetval;
	struct sockaddr_in sock_addr;
	char *hostname;
	hostname=(char*)malloc(NI_MAXHOST*sizeof(char));
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

void thread_get_host_info(int index,char *ip) {
	if (ip == NULL) {
		return;
	}
	responses[index].ip = ip;
	//printf("\n\nUpdate thread %d %s \n\n", index,ip);
	hostent *host_name = gethostbyname(ip);
	if (host_name == NULL) {
		char *n = "< no DNS entry >";
		responses[index].host_name = n;
		printf("Yo\n");
		return;
	}
	char* host= getnamefromip(host_name->h_name);
	bool areSame = false;
	string s1 = string(ip);
	string s2 = string(host);
	areSame = s1.compare(s2) == 0;
	if (host != NULL && !areSame)
		responses[index].host_name = host;
	else {
		char *n = "< no DNS entry >";
		responses[index].host_name = n;
		printf("Yo\n");
	}
}

//updates index_of_awaited_packets based on min timeout. This updates the timeout as well
void update_min_timeout_for_not_received_packet() {
	while (timeouts_interval.size()>0) {
		t = get_root_from_min_heap();
		rto = t.timeout;  //starting rto is 500 ms i.e. 500000 microseconds
		index_of_awaited_packet = t.index;
		rto = rto * 1e3;		
		timeout.tv_sec = (long)((double)rto / 1e6);
		timeout.tv_usec = rto;
		if (responses[index_of_awaited_packet].time_received == 0) {  //if this is the timeout consideration for packet that has not been received, we can go to the packet
			return;
		}
	}
}

//1e3 added because I changed time computation to microseconds
long getTimeoutForRetransmissionPacket(int index) {
	if (!(index >= 0 && index < 30)) {
		return 0;
	}
	long timeout = 0;
	if (index == 0) {
		if (responses[1].time_received > responses[1].time_sent) {
			timeout= (long)(1 * (responses[1].time_received - responses[1].time_sent)/(double)(1e3));  //same as the average time to receive from the next socket
		}
		else {
			timeout= 500;  //instead of 500 come up with something
		}
	}
	else if (index == 29) {
		if (responses[28].time_received > responses[28].time_sent) {
			timeout=(long)(2 * (responses[28].time_received - responses[28].time_sent)/(double)1e3);
		}
		else {
			timeout=1000;  //instead of this comeup with something
		}
	}
	else {
		if (responses[index - 1].time_received > responses[index-1].time_sent && responses[index + 1].time_received > responses[index+1].time_sent) {
			timeout= (long)(2*((double)((responses[index - 1].time_received - responses[index - 1].time_sent) + (responses[index + 1].time_received - responses[index + 1].time_sent))/(double)2*1e3));
		}
		else if (responses[index - 1].time_received > responses[index-1].time_sent) {
			timeout= (long)((responses[index - 1].time_received - responses[index - 1].time_sent)/(double)1e3);
		}
		else if(responses[index+1].time_received>responses[index+1].time_sent){
			timeout= (long)(((responses[index + 1].time_received - responses[index + 1].time_sent))/(double)1e3);
		}
		else {
			timeout= 500l;
		}
	}

	return timeout;
}



int receive_icmp_response(SOCKET sock, struct sockaddr_in remote)
{	
	int cnt = 0;	
	u_char *rec_buf = (u_char*)malloc(MAX_REPLY_SIZE * sizeof(u_char));  /* this buffer starts gethostname an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

	while (cnt<10) 
	{		
		if (timeouts_interval.size() == 0) {
			printf("No elements to wait\n");
			return 1;
		}
				
		DWORD timeout = 1000;
		
		//update_min_timeout_for_not_received_packet();  //this always removes an element
		int totalSizeOnSelect = WSAEventSelect(sock,event_icmp,FD_READ);
		if (totalSizeOnSelect == SOCKET_ERROR) {
			printf("Select failed with %d \n", WSAGetLastError());
			return SOCKET_ERROR;
		}		
		int select = WaitForSingleObject(event_icmp,timeout);
		switch (select) 
		{
			case WAIT_OBJECT_0: 
			{				
				int recv = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);			
				if (recv == SOCKET_ERROR) {
					printf("Error in receive %d \n", WSAGetLastError());
					return recv;
				}
				int sequence = 0;

				printf("***********Receive response %d and sequence is %d id is %d\n", recv, router_icmp_hdr ->seq, router_icmp_hdr->id);

				/*if (router_icmp_hdr->type==ICMP_ECHO_REPLY && router_icmp_hdr->id==ID ) {
					sequence = router_icmp_hdr->seq;
					responses[sequence].isReceived_ICMP_ECHO_REPLY = true;
					WSAResetEvent(event_icmp);
					printf("ICMP ECHO REPLY at sequence %d \n",sequence);
					timeouts_interval.push_back(t);
					break;
				}*/


				
				
				/*if (orig_icmp_hdr->seq != index_of_awaited_packet && responses[index_of_awaited_packet].num_probes<3) {
					Timeouts timeout;
					timeout.index = index_of_awaited_packet;
					long timeout_expected_for_new_retransmission = getTimeoutForRetransmissionPacket(index_of_awaited_packet);
					timeout.timeout = timeout_expected_for_new_retransmission;
					timeouts_interval.push_back(timeout);
				}*/

				printf("<-- * code %d and type %d PROTOCOL is %d id is %d sequence %d \n", router_icmp_hdr->code, router_icmp_hdr->type, orig_ip_hdr->proto, orig_icmp_hdr->id,orig_icmp_hdr->seq);
				
				if ((router_icmp_hdr->type==ICMP_TTL_EXPIRED || router_icmp_hdr->type==ICMP_DEST_UNREACH || router_icmp_hdr->type==ICMP_ECHO_REPLY) && router_icmp_hdr->code==0)
				{		
					if (orig_ip_hdr->proto == IPPROTO_ICMP) {
						if (orig_icmp_hdr->id == ID) {
							sequence = orig_icmp_hdr->seq;
							u_long ip_address_of_router = router_ip_hdr->source_ip;
							sockaddr_in dns_sock;
							dns_sock.sin_addr.s_addr = ip_address_of_router;
							char* ip = inet_ntoa(dns_sock.sin_addr);
							//Ping_Results ping_result;
							responses[sequence].time_received = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
							responses[sequence].ttl = sequence;  //sequence number of packet sent
							responses[sequence].rtt = ((double)(responses[sequence].time_received - responses[sequence].time_sent) / (1e3));
							responses[sequence].isReceived = true;
							thread_updater[sequence] = thread(thread_get_host_info, sequence, ip);
							if (thread_updater[sequence].joinable()) {
								thread_updater[sequence].join();
							}
							printf("Updated\n");
						}
					}
					/*sequence = orig_icmp_hdr->seq;   //sequence number is the ttl
					if (responses[sequence].isReceived == true) {
					}
					else if (orig_ip_hdr->proto == IPPROTO_ICMP)
					{
						// check if process ID matches
						u_long ip_address_of_router = router_ip_hdr->source_ip;
						sockaddr_in dns_sock;
						dns_sock.sin_addr.s_addr = ip_address_of_router;
						char* ip = inet_ntoa(dns_sock.sin_addr);
						//Ping_Results ping_result;
						responses[sequence].time_received = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
						responses[sequence].ttl = sequence;  //sequence number of packet sent
						responses[sequence].rtt = ((double)(responses[sequence].time_received - responses[sequence].time_sent) / (1e3));
						responses[sequence].isReceived = true;
						thread_updater[sequence] = thread(thread_get_host_info, sequence, ip);
					}*/
					
				}
				WSAResetEvent(event_icmp);
				break;
			}
			case WAIT_TIMEOUT: {
				//if packet that we are expecting has not been received, then only retransmit, and the number of probes for this should be less than 3
				printf("Total size on select is 0\n");
				cnt++;
				return 1;
				/*if (responses[index_of_awaited_packet].isReceived == false && responses[index_of_awaited_packet].num_probes<3 &&
					responses[index_of_awaited_packet].isReceived_ICMP_ECHO_REPLY==false) 
				{
					long timeout_expected_for_new_retransmission = getTimeoutForRetransmissionPacket(index_of_awaited_packet);
					responses[index_of_awaited_packet].num_probes++;
					responses[index_of_awaited_packet].time_sent = timeGetTime();
					rto = timeout_expected_for_new_retransmission;
					rto = rto * 1e3;
					Timeouts timeout;
					timeout.index = index_of_awaited_packet;
					timeout.timeout = timeout_expected_for_new_retransmission;
					timeouts_interval.push_back(timeout);
					//sending part
					int status = -1;
					if (responses[index_of_awaited_packet].isReceived == false)
					{
						status = send_icmp_packet(index_of_awaited_packet, sock, remote);
					}
				}*/
				break;
		}
	} //switch statement
		
	}	
}


int main(int argc, char *argv[]){
		
	if (argc != 2) {
		printf("Invalid number of arguments \n");
		return 1;
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "Main:\t WSAStartup Failed " << WSAGetLastError() << endl;
		return 1;
	}
	char* destination_ip = argv[1];
	struct sockaddr_in remote = fetchServer(destination_ip);


	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	

	//************MAKE THE HEAP FOR TIMEOUTS********************
	
	//line that makes a min heap
	std::make_heap(timeouts_interval.begin(), timeouts_interval.end(),GREATER());


	//*******************************************************


	// ********IP ADDRESS FROM HOST *****************
	

	//*********** SERVER CODE *******************
	
	
	
	//*************************************************************
	


	//************SEND ICMP BUFFER******************************
	//send all the icmp packets immediately (30 packets)
	for (int ttl = 0; ttl < 30; ttl++) {
		responses[ttl].num_probes++;
		responses[ttl].time_sent = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		//update of future_retx_times
		Timeouts timeout;
		timeout.index = ttl;
		timeout.timeout = 500;
		timeouts_interval.push_back(timeout);
		//sending part
		int status = -1;
		status = send_icmp_packet(ttl, sock, remote);
		
	}
	receive_icmp_response(sock, remote);
	receive_icmp_response(sock,remote);
	for (int i = 0; i < 30; i++) {
		if (thread_updater[i].joinable())
		{
			thread_updater[i].join();
		}
	}

	printf("\n\nFinal Results\n\n");
	for (int i = 1; i < responses.size(); i++) {
		if (responses[i].isReceived_ICMP_ECHO_REPLY == true) {
			return 0;
		}
		if (responses[i].isReceived == true) {
			printf("%d\t%s\t(%s)\t%0.3f ms\t(%d)\n", responses[i].ttl,  responses[i].host_name, responses[i].ip, responses[i].rtt, responses[i].num_probes);
		}
		else if(responses[i].isReceived==false){
			printf("%d\t*\n",i);
		}
	}
	
}

