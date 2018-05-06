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
#include <iostream>
#include <fstream>
#include <math.h>

#define CURRENT_TIME_H

#include <chrono>
#include <cstdint>
#define MAX_HOPS 30
#define BATCH_MAX_SIZE 10001


//href:// Notes from classes, hw2 pdf


using namespace std;


//href:// taken from HW1 submission of my own 
Timeouts t;   //contains time in milliseconds

int index_of_awaited_packet = 0;
vector<Ping_Results> responses(MAX_HOPS);
//vector<long> time_packets_sent(MAX_HOPS);
vector<Timeouts> timeouts_interval(0);  //this is a min heap
std::thread thread_updater[MAX_HOPS];   //max 30 threads in parallel
static int thread_num = 0;
DWORD ID = GetCurrentProcessId();
SOCKET sock;
HANDLE event_icmp = WSACreateEvent();
static bool can_end_on_timeout = false;
static int smallest_index_echo_response = MAX_HOPS-1;
static bool batch_mode_received_echo = false;
int total_sent = 0;
struct sockaddr_in remote;

//these are times in milliseconds
double per_hop_timeout = 0;
double timeout_delta = 110.0;
int n = 0;

map<u_long, int>batch_ip_vs_occurrences;
map<int,int> batch_timed_bucket_url_count;
int batch_counts_url_per_hop[MAX_HOPS];

vector<char*> batch_ip_with_more_than_30_hops;

DWORD batch_start = timeGetTime();

void reinit() {
	batch_start = timeGetTime();
	index_of_awaited_packet = 0;
	responses=vector<Ping_Results>(MAX_HOPS);
	timeouts_interval=vector<Timeouts>(0);  //this is a min heap
	ID = GetCurrentProcessId();
	event_icmp = WSACreateEvent();
	can_end_on_timeout = false;
	smallest_index_echo_response = MAX_HOPS-1;
	total_sent = 0;
	//these are times in milliseconds
	per_hop_timeout = 0;
	timeout_delta = 10.0;
	n = 0;
}
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
	t = (timeouts_interval.back());
	timeouts_interval.pop_back();
	//printf("POPPED element %d and remaining size is %d",t.index,timeouts_interval.size());
	///(timeouts.begin(), timeouts.end(), GREATER());
	return t;
}

//works correctly
//href:// taken from my code in hw2
bool fetchServer(char* host)
{
	
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
			printf("Host Ent is null. Unable to fetch server %d\n",WSAGetLastError());

			return false;
		}
		//cout << inet_ntoa(addr)<<endl;
		
	}
	else {
		remote.sin_addr.S_un.S_addr = dwRetVal;
	}
	remote.sin_family = AF_INET;
	remote.sin_port = htons(80);
	return true;
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
	total_sent++;
	//printf("--> sequence %d, id %d,  ttl %d and status %d\n", icmp->seq,icmp->id, ttl,sendtostatus);
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

void update_per_hop_timeouts(int index) {
	n++;
	double time_to_receive = (long)(responses[index].time_received - responses[index].time_sent) / ((double)1e3);
	double time_per_hop_current = 0.0;
	if (index != 0) {
		time_per_hop_current = (double)(time_to_receive) / index;
	}
	double c = (double)(((n - 1)*per_hop_timeout + 1 * (time_per_hop_current)));
	c = c / n;
	per_hop_timeout = c;
}

//href: https://stackoverflow.com/questions/10564525/resolve-ip-to-hostname
void thread_get_host_info2(int index,char* ip) {
	struct addrinfo	*output = 0;
	int status = getaddrinfo(ip, 0, 0, &output);
	char host[512], port[128];
	int status2 = getnameinfo(output->ai_addr, output->ai_addrlen, host, 512, 0, 0, 0);
	responses[index].host_name = (char*)malloc(NI_MAXHOST);
	bool areSame = false;
	areSame = strcmp(host, ip) == 0;
	if (host != NULL && !areSame)
	{
		strcpy(responses[index].host_name, host);
	}
	else {
		char *n = "< no DNS entry >";
		strcpy(responses[index].host_name, n);
	}

	//printf("Host is %s \n", host);
	freeaddrinfo(output);
}

void thread_get_host_info_unused(int index,char *ip) {
	//printf("IN DNS %d\n", index);
	if (ip == NULL) {
		return;
	}

	//********************************************************************
	//compute the per_hop_timeouts
	update_per_hop_timeouts(index);
	//*********************************************************************
	char *host = getnamefromip(ip);
	bool areSame = false;
	areSame = strcmp(host, ip) == 0;
	responses[index].host_name = (char*)malloc(NI_MAXHOST);
	if (host != NULL && !areSame)
	{
		strcpy(responses[index].host_name, host);
	}
	else {
		char *n = "< no DNS entry >";
		strcpy(responses[index].host_name, n);
	}
	//printf("OUT DNS %d\n", index);
}

//updates index_of_awaited_packets based on min timeout. This updates the timeout as well
void update_min_timeout_for_not_received_packet() {
	if(timeouts_interval.size()>0) {
		t = get_root_from_min_heap();
		index_of_awaited_packet = t.index;		
	}
}

long getTimeoutForRetransmissionPacket2(int index) {
	if (!(index >= 0 && index < MAX_HOPS)) {
		return 0;
	}
	//printf("\t\t\t index %d, per_hop_timeout %li", index, per_hop_timeout);
	double timeout_d=(index * per_hop_timeout) + timeout_delta;
	long timeout = (long)timeout_d;
	timeout = timeout;
	return timeout;
	
}

//1e3 added because I changed time computation to microseconds
long getTimeoutForRetransmissionPacket(int index) {
	if (!(index >= 0 && index < MAX_HOPS)) {
		return 0;
	}
	long timeout = 0;
	if (index == 0) {
		if (responses[1].time_received > responses[1].time_sent) {
			timeout= (long)(1 * (responses[1].time_received - responses[1].time_sent)/(double)(1e3));  //same as the average time to receive from the next socket
		}
		else {
			timeout= 100;  //instead of 500 come up with something
		}
	}
	else if (index == MAX_HOPS-1) {
		if (responses[MAX_HOPS-2].time_received > responses[MAX_HOPS-2].time_sent) {
			timeout=(long)(2 * (responses[MAX_HOPS-2].time_received - responses[MAX_HOPS-2].time_sent)/(double)1e3);
		}
		else {
			timeout=100;  //instead of this comeup with something
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
			timeout= 100l;
		}
	}
	//printf("\t\t computed timeout %li",timeout);
	return timeout;
}



int receive_icmp_response(SOCKET sock, struct sockaddr_in remote,bool check_dns)
{	
	int cnt = 0;	
	u_char *rec_buf = (u_char*)malloc(MAX_REPLY_SIZE * sizeof(u_char));  /* this buffer starts gethostname an IP header */
	IPHeader *router_ip_hdr = (IPHeader *)rec_buf;
	ICMPHeader *router_icmp_hdr = (ICMPHeader *)(router_ip_hdr + 1);
	IPHeader *orig_ip_hdr = (IPHeader *)(router_icmp_hdr + 1);
	ICMPHeader *orig_icmp_hdr = (ICMPHeader *)(orig_ip_hdr + 1);
	bool in_loop = true;
	while (in_loop) 
	{		
		if (timeouts_interval.size() == 0) {
			printf("No elements to wait\n");
			return 1;
		}		
		//setup retransmission timeout
		update_min_timeout_for_not_received_packet();
		DWORD retx_timeout = (DWORD)(t.timeout);  //timeout in milliseconds
		int totalSizeOnSelect = WSAEventSelect(sock,event_icmp,FD_READ);
		if (totalSizeOnSelect == SOCKET_ERROR) {
			printf("Select failed with %d \n", WSAGetLastError());
			return SOCKET_ERROR;
		}
		//printf("Retransmission timeout %d\n", (int)(retx_timeout));
		int select = WaitForSingleObject(event_icmp,retx_timeout);
		switch (select) 
		{			
			case WAIT_TIMEOUT:
			{
				/*if (!check_dns) {//batch mode
					in_loop = false;
					break;
				}*/
				//retransmit all not received packets less than packet sequence at echo reply
				bool atleast_one_retransmitted = false;
				//remove everything from the timeouts_interval
				timeouts_interval.clear();
				for (int i = 1; i<=smallest_index_echo_response; i++) {
					if (!responses[i].isReceived && responses[i].num_probes<3) {
						responses[i].num_probes++;
						responses[i].time_sent= std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
						responses[i].num_probes++;
						send_icmp_packet(i, sock, remote);
						Timeouts t;
						t.index = i;
						t.timeout=  getTimeoutForRetransmissionPacket2(i);
						timeouts_interval.push_back(t);
						atleast_one_retransmitted = true;
						//printf("Retx --> %d and size of time_interval %d\n", i, timeouts_interval.size());
					}
				}
				in_loop = atleast_one_retransmitted;
				break;
			}
			case WAIT_OBJECT_0: 
			{
				bool found_new = false;
				int recv = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, NULL, NULL);			
				if (recv == SOCKET_ERROR) {
					printf("Error in receive %d \n", WSAGetLastError());
					return recv;
				}
				//first time when ICMP_ECHO_RESPONSE IS RECEIVED, handle it

				if (router_icmp_hdr->code == 0 && (router_icmp_hdr->type == ICMP_ECHO_REPLY || router_icmp_hdr->type == ICMP_TTL_EXPIRED))
				{
					if (orig_ip_hdr->proto == IPPROTO_ICMP)
					{
						//batch mode
						if (!check_dns) {
							if (router_icmp_hdr->type == ICMP_ECHO_REPLY) 
							{
								if (router_icmp_hdr->id == ID && !responses[router_icmp_hdr->seq].isReceived) 
								{
									batch_mode_received_echo = true;
									u_long ip=router_ip_hdr->source_ip;
									if (batch_ip_vs_occurrences.find(ip) != batch_ip_vs_occurrences.end()) {
										batch_ip_vs_occurrences[ip]++;
									}
									else {
										batch_ip_vs_occurrences[ip]=1;
									}
									smallest_index_echo_response = min(router_icmp_hdr->seq, smallest_index_echo_response);
									responses[router_icmp_hdr->seq].isReceived = true;
									
									//time in milliseconds. Bin size is 50 ms
									long elapsedtime = timeGetTime() - batch_start;
									int id = ceil((double)elapsedtime / 50);
									//printf("id in time_array == %d", id);
								}
							}

							else {
								if (orig_icmp_hdr->id == ID && responses[orig_icmp_hdr->seq].isReceived == false) {
									u_long ip = router_ip_hdr->source_ip;
									if (batch_ip_vs_occurrences.find(ip) != batch_ip_vs_occurrences.end()) {
										batch_ip_vs_occurrences[ip]++;
									}
									else {
										batch_ip_vs_occurrences[ip]=1;
									}
									responses[orig_icmp_hdr->seq].isReceived = true;
								}
							}
						}
						else {
							//handle ICMP ECHO REPLY
							if (router_icmp_hdr->type == ICMP_ECHO_REPLY) {
								if (router_icmp_hdr->id == ID && !responses[router_icmp_hdr->seq].isReceived) {
									smallest_index_echo_response = min(router_icmp_hdr->seq, smallest_index_echo_response);
									u_long ip_address_of_router = router_ip_hdr->source_ip;
									sockaddr_in dns_sock;
									dns_sock.sin_addr.s_addr = ip_address_of_router;
									char* ip = inet_ntoa(dns_sock.sin_addr);
									//Ping_Results ping_result;
									responses[router_icmp_hdr->seq].time_received = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
									responses[router_icmp_hdr->seq].ttl = router_icmp_hdr->seq;  //sequence number of packet sent
									responses[router_icmp_hdr->seq].rtt = ((double)(responses[router_icmp_hdr->seq].time_received - responses[router_icmp_hdr->seq].time_sent) / (1e3));
									responses[router_icmp_hdr->seq].isReceived = true;
									responses[router_icmp_hdr->seq].ip = (char*)malloc(NI_MAXHOST);
									strcpy(responses[router_icmp_hdr->seq].ip, ip);
									found_new = true;
									if (check_dns) {
										/*if (thread_updater[router_icmp_hdr->seq].joinable())
										{
											thread_updater[router_icmp_hdr->seq].join();
										}*/
										char *ip_copy = (char*)malloc(NI_MAXHOST);
										strcpy(ip_copy, ip);
										thread_updater[router_icmp_hdr->seq] = thread(thread_get_host_info2, router_icmp_hdr->seq, ip_copy);
									}

								}
							}
							else  //when not in batch mode
							{
								if (orig_icmp_hdr->id == ID && responses[orig_icmp_hdr->seq].isReceived == false)
								{
									u_long ip_address_of_router = router_ip_hdr->source_ip;
									sockaddr_in dns_sock;
									dns_sock.sin_addr.s_addr = ip_address_of_router;
									char* ip = inet_ntoa(dns_sock.sin_addr);
									//Ping_Results ping_result;
									responses[orig_icmp_hdr->seq].time_received = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
									responses[orig_icmp_hdr->seq].ttl = orig_icmp_hdr->seq;  //sequence number of packet sent
									responses[orig_icmp_hdr->seq].rtt = ((double)(responses[orig_icmp_hdr->seq].time_received - responses[orig_icmp_hdr->seq].time_sent) / (1e3));
									responses[orig_icmp_hdr->seq].isReceived = true;
									responses[orig_icmp_hdr->seq].ip = (char*)malloc(NI_MAXHOST);
									strcpy(responses[orig_icmp_hdr->seq].ip, ip);
									found_new = true;
									if (check_dns) {
										/*if (thread_updater[orig_icmp_hdr->seq].joinable())
										{
											thread_updater[orig_icmp_hdr->seq].join();
										}*/

										char *ip_copy = (char*)malloc(NI_MAXHOST);
										strcpy(ip_copy, ip);
										thread_updater[orig_icmp_hdr->seq] = thread(thread_get_host_info2, orig_icmp_hdr->seq, ip_copy);
									}
								} //if ends here


							}

						}

					}
				} //outer if
				else{   //here we will handle errors
					if (orig_ip_hdr->proto == IPPROTO_ICMP && orig_icmp_hdr->id == ID)  //i.e. protocol is ICMP and id is same
					{
						u_long ip_address_of_router = router_ip_hdr->source_ip;
						sockaddr_in dns_sock;
						dns_sock.sin_addr.s_addr = ip_address_of_router;
						char* ip = inet_ntoa(dns_sock.sin_addr);
						printf("Router IP %s responded with error type %d and error code %d\n",ip,router_icmp_hdr->type,router_icmp_hdr->code);
						if (router_icmp_hdr->type == ICMP_DEST_UNREACH) {
							return 1;
						}
					}
				}
				WSAResetEvent(event_icmp);
				if (!found_new) 
				{
					timeouts_interval.push_back(t);
				}
				break;
			}
			

	} //switch statement
		if (timeouts_interval.size() == 0) {
			return 1;
		}
	}	
}

char* extract_url(string host) {
	if (host.length() == 0) {
		return "";
	}
	int i1=host.find("http://");
	int i2=host.find("https://");
	//removed http and https
	if (i2 >= 0) {
		host = host.substr(i2+5+3,host.length());
	}
	else if (i1 >= 0) {
		host = host.substr(i1 + 4+3, host.length());
	}
	int index_of_slash = host.find_first_of("/");
	int index_of_hash = host.find_first_of("#");
	int index_of_question = host.find_first_of("?");
	if (index_of_hash <0) {
		index_of_hash = BATCH_MAX_SIZE;
	}
	if (index_of_question <0) {
		index_of_question = BATCH_MAX_SIZE;
	}
	if (index_of_slash < 0) {
		index_of_slash = BATCH_MAX_SIZE;
	}

	int min1 = min(index_of_hash, index_of_question);
	int min2 = min(min1, index_of_slash);

	if (min2 < host.length()) {
		host = host.substr(0,min2);
	}

	char *temp_ch = (char*)malloc(host.length()+1);
	strcpy(temp_ch,host.c_str());
	printf("%s\n", temp_ch);
	return temp_ch;	
}
string convert_char_to_string(char* arr) {
	if (arr == NULL || strlen(arr)==0) {
		return "";
	}
	string temp = "";
	for (int i = 0; i < strlen(arr); i++) {
		temp += arr[i];
	}
	return temp;
}

int main(int argc, char *argv[]){
		
	if (argc != 2 && argc!=1) {
		printf("Invalid number of arguments \n");
		return 1;
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		cout << "Main:\t WSAStartup Failed " << WSAGetLastError() << endl;
		return 1;
	}
	//batch mode
	if (argc == 1) {
		
		for (int i = 0; i < MAX_HOPS; i++) {
			batch_counts_url_per_hop[i] = 0;
		}
		ifstream in("10k_urls.txt");
		if (!in) {
			cout << "Cannot open input file.\n";
			return 1;
		}
		char *destination_ips[BATCH_MAX_SIZE];
		int index = 0;
		for (int i = 0; i < BATCH_MAX_SIZE; i++) {
			destination_ips[i] = (char*)malloc(NI_MAXHOST);
		}
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (sock == INVALID_SOCKET)
		{
			printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}
		index = 0;
		while (in) {
			in.getline(destination_ips[index++],100000);
		}
		for (int i = 0; i < BATCH_MAX_SIZE; i++) {
			reinit();
			//printf("IP* from array %s",destination_ips[i]);
			string ipstr = convert_char_to_string(destination_ips[i]);
			char* destination_ip = extract_url(ipstr);
			//printf("IP %s\n", destination_ip);
			bool fetched= fetchServer(destination_ip);
			if (!fetched) {
				continue;
			}
			//************MAKE THE HEAP FOR TIMEOUTS********************
			//line that makes a min heap
			std::make_heap(timeouts_interval.begin(), timeouts_interval.end(), GREATER());
			//************SEND ICMP BUFFER******************************
			//send all the icmp packets immediately (30 packets)
			for (int ttl = 0; ttl < MAX_HOPS; ttl++) {
				responses[ttl].num_probes++;
				responses[ttl].time_sent = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
				Timeouts timeout;
				timeout.index = ttl;
				timeout.timeout = 500;
				timeouts_interval.push_back(timeout);
				//sending part
				int status = -1;
				status = send_icmp_packet(ttl, sock, remote);
			}
			receive_icmp_response(sock, remote, false);
			long timeEl = timeGetTime()-batch_start;
			
			printf("[%d] = %d\n",i,smallest_index_echo_response);
			
			
			if (batch_mode_received_echo == true) {
				batch_counts_url_per_hop[smallest_index_echo_response]++;
			}			
			if (smallest_index_echo_response >30 && batch_mode_received_echo==true) {
				batch_ip_with_more_than_30_hops.push_back(destination_ip);
				printf("~~~~~~~~~~~~~~Found IP with more than 30 hops %s\n",batch_ip_with_more_than_30_hops.end());
				//strcpy(batch_ip_with_more_than_30_hops, destination_ip);
			}

			int time_bucket = ceil((double)timeEl / 50);
			printf("elapsed time %li and bucket is %d \n", timeEl, time_bucket);

			//if the packet is not received, no point of adding it to the bucket
			if (batch_mode_received_echo == true) 
			{
				if (batch_timed_bucket_url_count.find(time_bucket) != batch_timed_bucket_url_count.end()) {
					batch_timed_bucket_url_count[time_bucket]++;
				}
				else {
					batch_timed_bucket_url_count[time_bucket] = 1;
				}
			}
			batch_mode_received_echo = false;
			
		}
		ofstream myfile;
		myfile.open("output-10k.txt");
		for (int i = 0; i < MAX_HOPS; i++) {
			printf("Writing hops count\n");
			myfile << "i = "<<i<<" URLS = "<<batch_counts_url_per_hop[i]<<endl;
		}
		if (batch_ip_with_more_than_30_hops.size() > 0) {
			myfile << "IPs with more than 30 hops" << endl;
			for (int i = 0; i < batch_ip_with_more_than_30_hops.size(); i++) {
				myfile <<batch_ip_with_more_than_30_hops[i] << endl;
			}
		}
			
		myfile.close();		

		myfile.open("output-10k-timewindow.txt");
		map <int, int> ::iterator itr;
		for (itr = batch_timed_bucket_url_count.begin(); itr != batch_timed_bucket_url_count.end(); ++itr)
		{
			printf("key=%d value=%d\n", itr->first, itr->second);
			myfile << "i = " << itr->first << " time = " << (itr->first + 1) * 50 << " URLS = " <<itr->second << endl;
		}
		myfile.close();

		myfile.open("output-10k-unique-url.txt");
		map <u_long, int> ::iterator itr1;
		int total_num_routers = 0,unique_routers=0;
		for (itr1 = batch_ip_vs_occurrences.begin(); itr1 != batch_ip_vs_occurrences.end(); ++itr1)
		{
			printf("key=%li value=%d\n", itr1->first, itr1->second);
			
			total_num_routers += itr1->second;
			unique_routers += 1;
			//display only unique ips
			if (itr1->second == 1)
			{
				u_long ip_address_of_router = itr1->first;
				sockaddr_in dns_sock;
				dns_sock.sin_addr.s_addr = ip_address_of_router;
				char* ip = inet_ntoa(dns_sock.sin_addr);
				string str=convert_char_to_string(ip);
				myfile << str <<" count "<<itr1->second<< endl;
			}				
		}
		myfile << "Total Routers " << total_num_routers<< endl;
		myfile << "Unique Routers " << unique_routers << endl;

		myfile.close();		
	}

	if (argc == 2) {  //normal mode
		
		char* destination_ip = argv[1];
		string ipstr = convert_char_to_string(destination_ip);
		destination_ip = extract_url(ipstr);
		bool fetched = fetchServer(destination_ip);
		if (!fetched) {
			return 1;
		}
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (sock == INVALID_SOCKET)
		{
			printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}
		//************MAKE THE HEAP FOR TIMEOUTS********************
		//line that makes a min heap
		std::make_heap(timeouts_interval.begin(), timeouts_interval.end(), GREATER());
		//************SEND ICMP BUFFER******************************
		//send all the icmp packets immediately (30 packets)
		DWORD start_normal_mode = timeGetTime();
		for (int ttl = 0; ttl < MAX_HOPS; ttl++) {
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
		receive_icmp_response(sock, remote,true);
		DWORD received_end = timeGetTime();
		for (int i = 0; i < MAX_HOPS; i++) {
			if (thread_updater[i].joinable())
			{
				thread_updater[i].join();
			}
		}
		printf("Time taken for threads extra for DNS lookups %0.3f\n", (double)(timeGetTime() - received_end) / (1e3));


		DWORD end_time_nomral_mode = timeGetTime();
		for (int i = 1; i <= smallest_index_echo_response; i++) {
			if (responses[i].isReceived == true) {
				printf("%d\t%s\t(%s)\t%0.3f ms\t(%d)\n", responses[i].ttl, responses[i].host_name, responses[i].ip, responses[i].rtt, responses[i].num_probes);
			}
			else if (responses[i].isReceived == false) {
				printf("%d\t*\n", i);
			}
		}
		printf("Total execution time %li ms\n",(long)(end_time_nomral_mode-start_normal_mode));
	}
	
}

