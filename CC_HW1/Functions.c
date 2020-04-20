// Authors - Maor Naftali (ID 205882699) and Yuval Kogan (ID 310596424)
// Project - DNS Client
// Description - functions inplementation file of the DNS Client 
#define _CRT_SECURE_NO_WARNINGS

// Library Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Project Includes
#include "Defines.h"

// gethostbyname example includes
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

int CheckValidInput(const char *input_string) { // TODO - expend to more cefisticated checks?
	int dotOnPrev = 0;
	char *invalid_char = "!@#$%^&*()_+<>\\?:\"[]|';,";
	for (int i = 0; i < strlen(input_string); i++) {
		for (int j = 0; j < strlen(invalid_char); j++) {
			if (input_string[i] == invalid_char[j]) {
				return 0; //invalid input
			}
		}
		if (dotOnPrev == 1 && input_string[i] != '.') {
			dotOnPrev = 0;
		}
		if (input_string[i] == '.' && dotOnPrev == 0) {
			dotOnPrev = 1;
		}
		else if (input_string[i] == '.' && dotOnPrev == 1) {
			return 0; // two dots in a row (..)
		}
	}
	return 1; //valid input
};

int CheckIfQuit(const char *input_string) { // TODO - deal with shorter strings than quit
	char *is_quit = "quit";
	for (int i = 0; i < strlen(input_string); i++) {
		if (input_string[i] != is_quit[i]) {
			printf("CheckIfQuit returning 0\n");
			return 0; // not quit
		}
	}
	printf("CheckIfQuit returning 1\n");
	return 1; // all chars matches - quit
}

struct hostent GetHostByName1(const char *host_name) {
	WSADATA wsaData;
	int iResult;
	DWORD dwError;
	int i = 0;
	struct hostent *remoteHost;
	struct in_addr addr;
	char **pAlias;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
	}

	remoteHost = gethostbyname(host_name);
	if (remoteHost == NULL) {
		remoteHost = malloc(100 * sizeof(remoteHost));
		remoteHost->h_name = "NULL"; // cant return NULL structure, I decide how to check it. 
	}
	return *remoteHost;
};

void ConvertDomain(unsigned char* dest, unsigned char* source)
{
	int lock = 0, i;
	strcat((char*)source, ".");

	for (i = 0; i < strlen((char*)source); i++)
	{
		if (source[i] == '.')
		{
			*dest++ = i - lock;
			for (; lock<i; lock++)
			{
				*dest++ = source[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dest++ = '\0';
}

struct hostent dnsQuery(const char *host_name)
{

	unsigned char buf[65536], *qname;
//	struct RES_RECORD answer;
	unsigned short pointer = 0;
	
	struct Header *dns_header = NULL;
	struct Question *qinfo = NULL;
	struct hostent Response; 

	Response.h_addrtype = NULL;
	Response.h_addr_list = NULL;
	Response.h_aliases = NULL;
	Response.h_length = NULL;
	Response.h_name = NULL;
	

	dns_header = (struct Header *)&buf[pointer];
	
	dns_header->id = (unsigned short)htons(++counter_for_id);
	dns_header->qr = 0;
	dns_header->opcode = 0;
	dns_header->aa = 0; //Authoritative
	dns_header->tc = 0; 
	dns_header->rd = 0; //Recursive
	dns_header->ra = 0;
	dns_header->z = 0;
	dns_header->rcode = 0;

	dns_header->q_count = htons(1);
	dns_header->an_count = 0;
	dns_header->ns_count = 0;
	dns_header->ar_count = 0;
	printf("assigned DNS to buffer, moving pointer to next position\n");
	pointer += sizeof(struct Header);
	printf("The new pointer position is %d\n", pointer);

	//point to the query portion
	qname = (unsigned char*)&buf[pointer];
	pointer += (strlen((char*)qname) + 1);
	printf("The new pointer position is %d\n", pointer);

	ConvertDomain(qname, host_name);
	printf(" The qname converted is %s\n", qname);
	qinfo = (struct Question*)&buf[sizeof(struct Header) + (strlen((char*)qname) + 1)];

	qinfo->qtype = htons(1);
	qinfo->qclass = htons(1);//TODO rename

	pointer += sizeof(struct Question);
	printf("Sending Packet (size: %d)\n", pointer);
	int sent = sendto(s, (char*)buf, pointer, 0, (struct sockaddr*)&dest, sizeof(dest));
	printf("sendto (sent: %d)\n", sent);

	if (sent < 0)
	{
		perror("sendto failed");
	}
	printf("succeeded\n");
	
	//Todo add time limitaion 2sec

	int SenderAddrSize = sizeof(dest);//recvfrom uses pointer to size.

	printf("Recieving Packet\n");
	int recieved = recvfrom(s, (char*)buf, 65536, 0, (struct sockaddr*)&dest, &SenderAddrSize);
	printf("Recieved %d\n", recieved);

	if (recieved < 0)
	{
		perror("recvfrom failed\n");
	}
	printf("Done");

	pointer = 0;
	struct Parser *data = NULL;
	data = (struct Parser*) buf;
	printf("Buf : %s address: %s len: %d", (char*)buf, (char*)&buf, strlen(buf));
	//move ahead of the dns header and the query field
	unsigned short answers, fields, Rcode_mask, Rcode, QR;
	fields = ntohs(data->fields);
	answers = ntohs(data->an_count);
	Rcode_mask = 15;//0000 0000 0000 1111
	Rcode = Rcode_mask & fields;
	QR = fields / 65535; // 16bit divided by 16'b0;

	printf("\nThe response contains : ");
	printf("\n rcode %d ", Rcode);
	printf("\n QR %d.", Rcode);
	printf("\n %d Questions.", ntohs(data->q_count));
	printf("\n %d Answers.", ntohs(data->an_count));
	printf("\n %d Authoritative Servers.", ntohs(data->ns_count));
	printf("\n %d Additional records.\n\n", ntohs(data->ar_count));

	if (Rcode != 0) {
			//TODO implement
	}
	if (QR != 1) {
		//Not a response - implement
	}
	if (counter_for_id != ntohs(data->id)) {
		//TODO implement
	}
	if (ntohs(data->an_count) < 1){
		printf("num of Answers (%d) is lower than 1, returning NULL Response \n", ntohs(data->an_count));
		
		return Response;
	}
}