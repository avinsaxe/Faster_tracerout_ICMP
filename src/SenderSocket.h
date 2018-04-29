#pragma once
#include "common.h"
#include "SenderDataHeader.h"

using namespace std;
//href:// taken from hw3 shared by prof. Dmitri

#define STATUS_OK 0 // no error
#define ALREADY_CONNECTED 1 // second call to ss.Open() without closing connection
#define NOT_CONNECTED 2 // call to ss.Send()/Close() without ss.Open()
#define INVALID_NAME 3 // ss.Open() with targetHost that has no DNS entry
#define FAILED_SEND 4 // sendto() failed in kernel
#define TIMEOUT 5 // timeout after all retx attempts are exhausted
#define FAILED_RECV 6 // recvfrom() failed in kernel

#define MAX_ITERATIONS_SYN 3
#define MAX_ITERATIONS_FIN 5
#define MAX_ITERATIONS_DATA 50

class SenderSocket {
public:
	
	int index_in_buffer = 0;
	int next_index_in_buffer_to_send = 0;
	int packet_sequence_num = 0;
	int expected_packet_sequence_num = 0;
	int senderBase = 0;
	int packet_timedout = 0;
	int packet_fast_retransmitted = 0; 
	int effective_window = 0;
	float speed = 0.0f;
	
	//int coun = 0;
	float sampleRTT = 0.0f;
	float estimatedRTT = 0.0f;
	float prev_estimatedRTT = 0.0f;
	float devRTT = 0.0f;
	float prev_devRTT = 0.0f;
	float idealRate = 0.0f;

	//float averageRTT = 0.0f;
	float alpha = 0.125f;
	float beta = 0.25f;

	UINT64 data_sent_to_receiver = 0;  //number of bytes that have already been sent
	UINT64 data_acked_by_receiver = 0;  //number of bytes that have already been acked

	UINT64 offset = 0;  //number of bytes that have been made into packet and are in buffer or already sent
	
	Packet *pending_packets = NULL;  //shared buffer
	int W = 0;
	long rto = 1000000l;
	struct sockaddr_in remote;
	int DEFAULT_PORT = 0;
	DWORD checksum_sent=0;
	DWORD checksum_received = 0;
	DWORD start;
	SOCKET sock;
	SenderSocket();
	void reinit();
	void freeSocket();
	int open(char * destination_ip1);
	int close(char * destination_ip, int magic_port, int sender_window_packets, LinkProperties * lp, int *elapsedTime);
	int send(char * buf, int bytes);
	int worker();
};
