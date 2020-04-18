// Authors - Maor Naftali (ID 205882699) and Yuval Kogan (ID 310596424)
// Project - DNS Client
// Description - main file of the DNS Client - include headers and call main functions

// Project Includes

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
int main(int argc, char *argv[]) {
	if (argc < NUM_OF_INPUT_ARGUMENTS) { return ERR_CODE_NOT_ENOUGH_ARGUMENTS; };
	if (argc > NUM_OF_INPUT_ARGUMENTS) { return ERR_CODE_TOO_MANY_ARGUMENTS; };

	char *input_address;
	input_address = argv[1];
	int quit = 0;
	struct hostent *hostent_answer = malloc(5000 * sizeof(char));
	char *host_name;
	struct in_addr addr;
	int valid_input;
	while (quit == 0) {
		valid_input = CheckValidInput(input_address);
		if (valid_input == 0) { //invalid input
			printf("ERROR: BAD NAME\n");
		}
		else { //valid input
			// gethostbyname example
			host_name = input_address;
			*hostent_answer = GetHostByName1(host_name);
			// ******** Enter dnsQuery here **********

			// user interface using gethostbyname
			if (hostent_answer->h_name == "NULL") {
				printf("ERROR: NONEXISTENT\n");
			}
			else {
				int i = 0;
				// TODO - understand how this print works
				if (hostent_answer->h_addrtype == 2) { // ipv4
					while (hostent_answer->h_addr_list[i] != 0) {
						addr.s_addr = *(u_long *)hostent_answer->h_addr_list[i++];
						printf("%s\n", inet_ntoa(addr));
					}
				}
				// TODO - delete ipv6 because not in use?S
				else if (hostent_answer->h_addrtype == 26) // ipv6
					printf("\tRemotehost is an IPv6 address\n");
			}
		}
		scanf("%s", input_address);
		quit = CheckIfQuit(input_address);
	}

	return 0; // 0 if successful
};

