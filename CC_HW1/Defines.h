// Authors - Maor Naftali (ID 205882699) and Yuval Kogan (ID 310596424)
// Project - DNS Client
// Description - constant defines

#ifndef SOCKET_EXAMPLE_SHARED_H
#define SOCKET_EXAMPLE_SHARED_H
#define ERR_CODE_NOT_ENOUGH_ARGUMENTS	-99
#define ERR_CODE_TOO_MANY_ARGUMENTS		-98
#define NUM_OF_INPUT_ARGUMENTS			2
//#define HOST_NAME_NOT_FOUND				-987 // for GetHostByNAme
#define MAX_ADDR_LEN					100
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define A_TYPE 1

typedef int bool;
#define TRUE 1
#define FALSE 0

#endif // SOCKET_EXAMPLE_SHARED_H
extern int s;
extern char dns_server_address[100];
extern struct sockaddr_in dest;
extern short counter_for_id;
struct Header
{
	short id; //16 bit
	//----------------------
	char qr : 1; // query/response flag
	char opcode : 4;
	char aa : 1; // authoritive answer
	char tc : 1; // truncated
	char rd : 1; // recursion desired
	char ra : 1; // recursion available
	char z : 3;
	char rcode : 4; // response code
	//----------------------
	unsigned short q_count; // number of question entries
	//----------------------
	unsigned short an_count; // answers count
	//----------------------
	unsigned short ns_count; // authoritive name server count
	//----------------------
	unsigned short ar_count; //  number of resource records in the Additional Records section
};

struct Parser
{
	short id; //16 bit
			  //----------------------
	unsigned short fields;
					//----------------------
	unsigned short q_count; // number of question entries
							//----------------------
	unsigned short an_count; // answers count
							 //----------------------
	unsigned short ns_count; // authoritive name server count
							 //----------------------
	unsigned short ar_count; //  number of resource records in the Additional Records section
};

struct Question
{
	unsigned short qtype;
	unsigned short qclass;
};

