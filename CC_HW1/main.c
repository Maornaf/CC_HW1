// Authors - Maor Naftali (ID 205882699) and Yuval Kogan (ID 310596424)
// Project - DNS Client
// Description - main file of the DNS Client - include headers and call main functions

// Project Includes
#define _CRT_SECURE_NO_WARNINGS

#include "DNSClient.h"
//#include "Functions.c"
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
#pragma warning(disable:4996) // crt secure no warnings


// Description - main function the DNS Client - user interface
// Parameters - receives as a parameter ServerIp, ServerPort 
// Returns - 0 if succesful, error code otherwise
int s;
char dns_server_address[100];
struct sockaddr_in dest;
short counter_for_id;

int main(int argc, char *argv[]) {
	if (argc < NUM_OF_INPUT_ARGUMENTS) { return ERR_CODE_NOT_ENOUGH_ARGUMENTS; };
	if (argc > NUM_OF_INPUT_ARGUMENTS) { return ERR_CODE_TOO_MANY_ARGUMENTS; };

	strcpy(dns_server_address, argv[1]);
	char input_address[100];
	counter_for_id = 111;

	printf("dns_server_address is %s\n", dns_server_address);//TODO add verification for valid dns address
	//WSADATA
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
		printf("Error at WSAStartup()\n");


	//socket preparing
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	printf("socket num is %d\n", s);
	
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_server_address);
	printf("dest.sin_family %d dest.sin_port %d dest.sin_addr %s\n", dest.sin_family, ntohs(dest.sin_port), inet_ntoa(dest.sin_addr));
	struct hostent *hostent_answer = malloc(5000 * sizeof(char));
	char *host_name;
	struct in_addr addr;
	int valid_input;
	int quit = 0;
	while (1) {
		printf("please enter host name\n");
		scanf("%s", input_address);
		valid_input = CheckValidInput(input_address);
		quit = CheckIfQuit(input_address);
		printf("quit is %d\n", quit);

		if (quit != 0) {
			return 0;
		}
		if (valid_input == 0) { //invalid input
			printf("ERROR: BAD NAME\n");
			continue;
		}
		printf("calling GetHostByName\n");
		host_name = input_address;
		*hostent_answer = dnsQuery(host_name);
		//*hostent_answer = GetHostByName1(host_name);//TODO remove
		// ******** Enter dnsQuery here **********
		if (hostent_answer->h_name == NULL) {
			printf("ERROR: NONEXISTENT\n");
		}
		else {
			// TODO - maor explain yuvalko how works the print
			if (hostent_answer->h_addrtype == 2) { // ipv4
				if (hostent_answer->h_addr_list[0] != 0) {
					addr.s_addr = *(u_long *)hostent_answer->h_addr_list[0];
					printf("%s\n", inet_ntoa(addr));
				}
			}
			// TODO - delete ipv6 because not in use?
			else if (hostent_answer->h_addrtype == 26) // ipv6
				printf("\tRemotehost is an IPv6 address\n");
		}
		
		
	}

	return 0; // 0 if successful
};

