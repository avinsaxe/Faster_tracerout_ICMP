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
vector<Timeouts> timeouts_interval(30);  //this is a min heap
std::thread thread_updater[30];   //max 30 threads in parallel
static int thread_num = 0;

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
	int sendtostatus = sendto(sock, (char*)send_buf, sizeof(ICMPHeader), 0, (SOCKADDR *)&remote, sizeof(remote));
	if (sendtostatus == SOCKET_ERROR) {
		printf("WSAERROR  %d \n", WSAGetLastError());
		exit(1);
	}
	printf("--> id %d, sequence %d, ttl %d and status %d\n", icmp->id, icmp->seq, ip_h->ttl,sendtostatus);
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

void thread_get_host_info(int index,char *ip) {
	if (ip == NULL) {
		return;
	}
	//printf("Update thread %d \n", index);
	hostent *host_name = gethostbyname(ip);
	char *host = getnamefromip(ip);
	if(host!=NULL)
		responses[index].host_name = host;
	if(host_name!=NULL)
		responses[index].ip = host_name->h_name;
	printf("<-- sequence %d, host %s, ip %s, num_probes %d, rtt %.3f, packet_sent_time %li, packet_received_time %li \n", index, responses[index].host_name,responses[index].ip,responses[index].num_probes,responses[index].rtt,responses[index].time_sent,responses[index].time_received);
	

}

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


long getTimeoutForRetransmissionPacket(int index) {
	if (!(index >= 0 && index < 30)) {
		return 0;
	}
	long timeout = 0;
	if (index == 0) {
		if (responses[1].time_received > responses[1].time_sent) {
			timeout= 1 * (responses[1].time_received - responses[1].time_sent);  //same as the average time to receive from the next socket
		}
		else {
			timeout= 500;  //instead of 500 come up with something
		}
	}
	else if (index == 29) {
		if (responses[28].time_received > responses[28].time_sent) {
			timeout=2 * (responses[28].time_received - responses[28].time_sent);
		}
		else {
			timeout=4000;  //instead of this comeup with something
		}
	}
	else {
		if (responses[index - 1].time_received > responses[index-1].time_sent && responses[index + 1].time_received > responses[index+1].time_sent) {
			timeout= (long)2*((double)((responses[index - 1].time_received - responses[index - 1].time_sent) + (responses[index + 1].time_received - responses[index + 1].time_sent))/(double)2);
		}
		else if (responses[index - 1].time_received > responses[index-1].time_sent) {
			timeout= (responses[index - 1].time_received - responses[index - 1].time_sent);
		}
		else if(responses[index+1].time_received>responses[index+1].time_sent){
			timeout= (responses[index + 1].time_received - responses[index + 1].time_sent);
		}
		else {
			timeout= 500l;
		}
	}
	timeout = 50000;
	return timeout;
}



int receive_icmp_response(SOCKET sock) {
	
	int first_response_not_received = 0;
	
	
	
	int cnt = 0;
	while (true) {
		update_min_timeout_for_not_received_packet();
		fd_set fd;
		cnt++;
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
		if (totalSizeOnSelect == 0) {  //this is the timeout event

			/*
			     if index i has not been received, but i-1 and i+1 have been received
				    timeout_i = 2*((rtt_i-1 +rtt_i+1)/2)

				 if index i has not been received, and i-1 has not been received
				     timeout_i = 2*(rtt_i+1)

				 if index i has not been received and i+1 has not been received
				     timeout_i = 4*(rtt_i-1)    //as the timeout for closer one should be less

			*/
			//if packet that we are expecting has not been received, then only retransmit, and the number of probes for this should be less than 3
			if (responses[index_of_awaited_packet].isReceived == false && responses[index_of_awaited_packet].num_probes<3) {
				
				long timeout_expected_for_new_retransmission = getTimeoutForRetransmissionPacket(index_of_awaited_packet);
				responses[index_of_awaited_packet].num_probes++;
				responses[index_of_awaited_packet].time_sent = timeGetTime();
				
				Timeouts timeout;
				timeout.index = index_of_awaited_packet;
				timeout.timeout = timeout_expected_for_new_retransmission;
				timeouts_interval.push_back(timeout);
				//sending part
				int status = -1;
				status = send_icmp_packet(index_of_awaited_packet + 1, sock, remote);
				printf("Total Size on select %d\n", totalSizeOnSelect);
			}
			printf("*Total Size on select %d\n", totalSizeOnSelect);
			continue;
		}
		u_char rec_buf[MAX_REPLY_SIZE];  /* this buffer starts gethostname an IP header */
		int recv = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);
		if (recv == SOCKET_ERROR) {
			printf("Error in receive %d \n", WSAGetLastError());
			return recv;
		}

		IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
		ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
		if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == (u_char)0)
		{
			IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
			ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);

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

					//Ping_Results ping_result;
					responses[sequence].time_received = timeGetTime();
					responses[sequence].ttl = sequence;  //sequence number of packet sent
					responses[sequence].rtt = ((double)(responses[sequence].time_received - responses[sequence].time_sent) / (1e3));
					responses[sequence].isReceived = true;
					thread_updater[sequence] = thread(thread_get_host_info, sequence, ip);
					if (sequence == first_response_not_received) {
						first_response_not_received++;
					}
				}
			}
		}
		else if (router_icmp_hdr->type == ICMP_ECHO_REPLY) {
			//echo replies only have 28 bytes of the packet, and hence only routers sequence and id can be extracted, which should be same as our own
			int sequence = router_icmp_hdr->seq;
			if (router_icmp_hdr->id == GetCurrentProcessId()) {
				if (sequence >= first_response_not_received) {
					printf("Received echo reply from a router which is at some hops away. All previous are already computed\n");
					return 1;
				}
			}
		}
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

	string targetHostStr(targetHost);	
	//*****************************************************

	//*********** SERVER CODE *******************

	remote= fetchServer(targetHostStr);
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
	for (int ttl = 1; ttl <= 30; ttl++) {
		
		responses[ttl - 1].num_probes++;
		responses[ttl - 1].time_sent = timeGetTime();
		//update of future_retx_times
		timeouts_interval[ttl - 1].index = ttl - 1;
		timeouts_interval[ttl - 1].timeout = 500;
		//sending part
		int status = -1;
		status = send_icmp_packet(ttl, sock, remote);
	}
	receive_icmp_response(sock);
	
}

