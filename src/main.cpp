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
struct sockaddr_in remote;
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
void print_results() {
	for (int i = 0; i < responses.size(); i++) {
		Ping_Results pr = responses[i];
		int ttl=pr.ttl;
		char* host_name=pr.host_name;
		char* ip=pr.ip;
		int num_probes=pr.num_probes;
		double rtt=pr.rtt;
		
		printf("%d\t%s (%s) %.3f ms (%d)",ttl,host_name,ip,rtt,num_probes);
	}
}

sockaddr_in fetchServer(char* host)
{
	
	memset(&remote, 0, sizeof(struct sockaddr_in));	
	in_addr addr;
	char *hostAddr;
	
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
			printf("Host Ent is null. Unable to fetch server\n");
			exit(-1);
		}
		//cout << inet_ntoa(addr)<<endl;
		memcpy((char*)(&remote.sin_addr), host_ent->h_addr, host_ent->h_length);
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
	//IPHeader *ip_h = (IPHeader* )((ICMPHeader*)send_buf + 1);
	//ip_h->ttl = ttl;

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
	printf("Sendto status %d", sendtostatus);
	if (sendtostatus == SOCKET_ERROR) {
		printf("WSAERROR  %d \n", WSAGetLastError());
		exit(1);
	}
	printf("--> id %d, sequence %d, ttl %d and status %d\n", icmp->id, icmp->seq, ttl,sendtostatus);
//	printf("--> id %d, sequence %d, ttl %d and status %d\n", icmp->id, icmp->seq, ip_h->ttl,sendtostatus);
	return sendtostatus;
}



char* getnamefromip(char* ip) {
	//href:// msdn https://msdn.microsoft.com/en-us/library/windows/desktop/ms738532(v=vs.85).aspx
	DWORD dwRetval;
	printf("IPSSSSS IS %s", ip);
	
	struct sockaddr_in sock_addr;
	char *hostname;
	hostname=(char*)malloc(NI_MAXHOST*sizeof(char));
	char servInfo[NI_MAXSERV];
	u_short port = 22191;
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = inet_addr(ip);
	sock_addr.sin_port = htons(port);
	dwRetval = getnameinfo((struct sockaddr *) &sock_addr,sizeof(struct sockaddr),hostname,NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
	printf("\n%s", hostname);
	
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
	printf("\n\nUpdate thread %d %s \n\n", index,ip);
	hostent *host_name = gethostbyname(ip);
	if (host_name != NULL)
		responses[index].ip = host_name->h_name;
	else {
		return;
	}
	char* host= getnamefromip(host_name->h_name);

	if(host!=NULL)
		responses[index].host_name = host;
	
	
	printf("\n\n******  %s *********\n\n", host);

	printf("<-- sequence %d, host %s, ip %s, num_probes %d, rtt %.3f, packet_sent_time %li, packet_received_time %li \n", index, responses[index].host_name,responses[index].ip,responses[index].num_probes,responses[index].rtt,responses[index].time_sent,responses[index].time_received);
	

}

//updates index_of_awaited_packets based on min timeout. This updates the timeout as well
void update_min_timeout_for_not_received_packet() {
	while (timeouts_interval.size()>0) {
		t = get_root_from_min_heap();
		rto = t.timeout;  //starting rto is 500 ms i.e. 500000 microseconds
		index_of_awaited_packet = t.index;
		rto = 5000;
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
			timeout=4000;  //instead of this comeup with something
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



int receive_icmp_response(SOCKET sock) {
	
	int first_response_not_received = 0;
	fd_set fd;
	int cnt = 0;
	while (true) 
	{		
		cnt++;		
		DWORD timeout = 50000;
		FD_ZERO(&fd);
		FD_SET(sock, &fd);
		update_min_timeout_for_not_received_packet();
		//this function updates the timeout as well

		//int totalSizeOnSelect = select(0, &fd, NULL, NULL, &timeout);		
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
			u_char rec_buf[MAX_REPLY_SIZE];  /* this buffer starts gethostname an IP header */
			int recv = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);
			if (recv == SOCKET_ERROR) {
				printf("Error in receive %d \n", WSAGetLastError());
				return recv;
			}


			IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
			ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
			printf("--> * code %d and type %d\n", router_icmp_hdr->code, router_icmp_hdr->type);
			if (router_icmp_hdr->type == ICMP_ECHO_REPLY) {
				printf("Hoorahhh !! TYPE IS ECHO_REPLY\n");
				//echo replies only have 28 bytes of the packet, and hence only routers sequence and id can be extracted, which should be same as our own
				int sequence = router_icmp_hdr->seq;
				if (router_icmp_hdr->id == ID) {
					if (sequence >= first_response_not_received) {
						printf("Received echo reply from a router which is at some hops away. All previous are already computed\n");
						return 1;
					}
				}
			}

			if (router_icmp_hdr->code == (u_char)3) {
				printf("Hoorahhh !! Code is 3\n");
				IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
				ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
				int sequence = orig_icmp_hdr->seq;   //sequence number is the ttl
				if (responses[sequence].isReceived == true) {
				}
				else if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == ID) {
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
						thread_updater[sequence].detach();
						if (sequence == first_response_not_received) {
							first_response_not_received++;
						}
						return 0;

					}
				}
			}

			if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == (u_char)0)
			{
				printf("Hoorahhh !! TTL EXPIRED Code is 0\n");
				IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
				ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

				int sequence = orig_icmp_hdr->seq;   //sequence number is the ttl
													 //cout << "Sequence Received " << sequence << endl;
				if (responses[sequence].isReceived == true) {
				}
				else if (orig_ip_hdr->proto == IPPROTO_ICMP)
				{
					// check if process ID matches
					if (orig_icmp_hdr->id == ID)
					{
						u_long ip_address_of_router = router_ip_hdr->source_ip;
						sockaddr_in dns_sock;
						dns_sock.sin_addr.s_addr = ip_address_of_router;
						char* ip = inet_ntoa(dns_sock.sin_addr);

						//Ping_Results ping_result;

						responses[sequence].time_received = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
						responses[sequence].ttl = sequence;  //sequence number of packet sent
						responses[sequence].rtt = ((double)(responses[sequence].time_received - responses[sequence].time_sent) / (1e3));
						responses[sequence].isReceived = true;
						printf("***** ip is %s", ip);
						thread_updater[sequence] = thread(thread_get_host_info, sequence, ip);
						thread_updater[sequence].detach();
						if (sequence == first_response_not_received) {
							first_response_not_received++;
						}

					}
				}
			}
			WSAResetEvent(event_icmp);
			break;
		}
		case WAIT_TIMEOUT: {
			//if packet that we are expecting has not been received, then only retransmit, and the number of probes for this should be less than 3
			printf("Total size on select is 0\n");
			if (responses[index_of_awaited_packet].isReceived == false && responses[index_of_awaited_packet].num_probes<3) 
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
					status = send_icmp_packet(index_of_awaited_packet + 1, sock, remote);
				}
				//printf("Total Size on select %d\n", totalSizeOnSelect);
			}
			//printf("*Total Size on select %d\n", totalSizeOnSelect);
			break;
		}
	} //switch statement
		
		
		//keep updating the timeout everytime
		

	}	
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


	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock == INVALID_SOCKET)
	{
		printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
	

	//************MAKE THE HEAP FOR TIMEOUTS********************
	
	//line that makes a min heap
	std::make_heap(timeouts_interval.begin(), timeouts_interval.end(),GREATER());

	
	//*******************************************************


	// ********IP ADDRESS FROM HOST *****************
	string destination_ip= argv[1];

	//copying the targethost. Taken from hw3.3
	char* targetHost = (char*)malloc(destination_ip.length() + 1);
	memcpy(targetHost, destination_ip.c_str(), destination_ip.length() + 1);
	targetHost[destination_ip.length()] = 0;

	
	//*****************************************************

	//*********** SERVER CODE *******************
	printf("Target host string %s", targetHost);
	remote= fetchServer(targetHost);

	
	
	//*************************************************************
	


	//************SEND ICMP BUFFER******************************
	//send all the icmp packets immediately (30 packets)
	for (int ttl = 1; ttl <= 30; ttl++) {
		responses[ttl - 1].num_probes++;
		responses[ttl - 1].time_sent = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
		//update of future_retx_times
		Timeouts timeout;
		timeout.index = ttl - 1;
		timeout.timeout = 5000000;

		timeouts_interval.push_back(timeout);
		//sending part
		int status = -1;
		status = send_icmp_packet(ttl, sock, remote);
	}
	receive_icmp_response(sock);
	
}

