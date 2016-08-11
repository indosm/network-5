#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex>
#include "windivert.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#define MAXBUF 0xFFFF
#define MAXURL 4096

using namespace std;

//패킷 통신에 사용되는 여러 struct들에 대해서 정의해놓은 곳.
typedef struct
{
	char *domain;
	char *uri;
} URL, *PURL;
typedef struct
{
	UINT size;
	UINT length;
	PURL *urls;
} BLACKLIST, *PBLACKLIST;

typedef struct
{
	WINDIVERT_IPHDR  ip;
	WINDIVERT_TCPHDR tcp;
} PACKET, *PPACKET;
typedef struct
{
	PACKET header;
	UINT8 data[];
} DATAPACKET, *PDATAPACKET;

//위해 사이트를 들어갔을 경우 표시되는 웹 페이지
//받아라 무지개 빔!! 뵤비 위키덕분에 많은것을 배웠습니다.
const char block_data[] =
"HTTP/1.1 200 OK\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n"
"\r\n"
"<!doctype html>\n"
"<html>\n"
"\t<head>\n"
"\t\t<title>BLOCKED!</title>\n"
"\t</head>\n"
"\t<body>\n"
"\t\t<h1>BLOCKED!</h1>\n"
"\t\t<hr>\n"
"\t\t<p>Harmful URL DETECTED!!</p>\n"
"\t\t<p1>This URL has been blocked!</p1>\n"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #CD1039;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #FFb400;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #fff56e;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #52e252;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #0064ff;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #0000cd;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"padding: 5px; margin: 0px; margin-top: 15px; border: 3px solid #; background-color: #a390ee;border-radius: 4px;\"><div class = \"tp_link\" color : #000000; \"><b><div class=\"floatleft\"></div></b></div><div style=\"margin - top: .5em; color: #000000; \"></div></div>"
"<div style = \"font-size: 40pt;\"><b>받아라 무지개 빔!!</b>"
"\t</body>\n"
"</html>\n";


static void PacketInit(PPACKET packet);
static int __cdecl UrlCompare(const void *a, const void *b);
static int UrlMatch(PURL urla, PURL urlb);
static PBLACKLIST BlackListInit(void);
static void BlackListInsert(PBLACKLIST blacklist, PURL url);
static void BlackListSort(PBLACKLIST blacklist);
static BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);
static void BlackListRead(PBLACKLIST blacklist, const char *filename);
static BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data,
	UINT16 len);
static char * reverse(char * arr);


int __cdecl main(int argc, char **argv)
{
	HANDLE handle;
	WINDIVERT_ADDRESS addr;
	UINT8 packet[MAXBUF];
	UINT packet_len;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	PVOID payload;
	UINT payload_len;
	PACKET reset0;
	PPACKET reset = &reset0;
	PACKET finish0;
	PPACKET finish = &finish0;
	PDATAPACKET blockpage;
	UINT16 blockpage_len;
	PBLACKLIST blacklist;
	unsigned i;
	INT16 priority = 404; 

	//commandline을 통해 읽어올 text file을 정의하게 된다.
	if (argc != 2)
	{
		fprintf(stderr, "usage: %s [file.txt]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	blacklist = BlackListInit();
	BlackListRead(blacklist, argv[1]);
	BlackListSort(blacklist);
	//WinDivert를 하기 전 패킷 기본 설정을 한다.
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;
	blockpage = (PDATAPACKET)malloc(blockpage_len);
	if (blockpage == NULL)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);
	blockpage->header.ip.Length = htons(blockpage_len);
	blockpage->header.tcp.SrcPort = htons(80);
	blockpage->header.tcp.Psh = 1;
	blockpage->header.tcp.Ack = 1;
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);
	PacketInit(reset);
	reset->tcp.Rst = 1;
	reset->tcp.Ack = 1;
	PacketInit(finish);
	finish->tcp.Fin = 1;
	finish->tcp.Ack = 1;

	// WinDivert를 Open한다.
	handle = WinDivertOpen(
		"outbound && "              
		"ip && "                   
		"tcp.DstPort == 80 && "     
		"tcp.PayloadLength > 0",    
		WINDIVERT_LAYER_NETWORK, priority, 0
	);
	if (handle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");

	// 계속해서 돌아가면서, WinDivert를 통해 패킷을 읽고, 사이트가 걸리는지 조사를 한다.
	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len))
		{
			// Packet does not match the blacklist; simply reinject it.
			WinDivertHelperCalcChecksums(packet, packet_len,
				WINDIVERT_HELPER_NO_REPLACE);
			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
			{
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}

		//만약 유해사이트에 들어가게 되었다면,
		//Hijacking을 시도하게 된다.
		reset->ip.SrcAddr = ip_header->SrcAddr;
		reset->ip.DstAddr = ip_header->DstAddr;
		reset->tcp.SrcPort = tcp_header->SrcPort;
		reset->tcp.DstPort = htons(80);
		reset->tcp.SeqNum = tcp_header->SeqNum;
		reset->tcp.AckNum = tcp_header->AckNum;
		WinDivertHelperCalcChecksums((PVOID)reset, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		blockpage->header.ip.SrcAddr = ip_header->DstAddr;
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;
		blockpage->header.tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);
		addr.Direction = !addr.Direction;     // Reverse direction.
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}
	}
}

/*
* Initialize a PACKET.
*/
static void PacketInit(PPACKET packet)
{
	memset(packet, 0, sizeof(PACKET));
	packet->ip.Version = 4;
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);
	packet->ip.Length = htons(sizeof(PACKET));
	packet->ip.TTL = 64;
	packet->ip.Protocol = IPPROTO_TCP;
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);
}

/*
* Initialize an empty blacklist.
*/
static PBLACKLIST BlackListInit(void)
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));
	UINT size;
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;
	blacklist->urls = (PURL *)malloc(size * sizeof(PURL));
	if (blacklist->urls == NULL)
	{
		goto memory_error;
	}
	blacklist->size = size;
	blacklist->length = 0;

	return blacklist;

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}

/*
* Insert a URL into a blacklist.
*/
static void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size * sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;
}

/*
* Sort the blacklist (for searching).
*/
static void BlackListSort(PBLACKLIST blacklist)
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}

/*
* Match a URL against the blacklist.
*/
static BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)
{
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;
		}
	}
	return FALSE;
}



static void BlackListRead(PBLACKLIST blacklist, const char *filename)
{
	//argv[1]로 부터 URL을 읽게 되는데, regex를 이용해, 어떠한 URL이든 처리하게 해준다.
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");
	char str[MAXURL * 2 + 2];
	string reg;
	if (file == NULL)
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}

	regex pattern("(https?://)?(www.)?([^/\n]+)([^\n]*)(\n)");
	while (fgets(str, MAXURL * 2 + 2, file) != NULL)
	{
		smatch m;
		reg = string(str);
		if (regex_search(reg, m, pattern))
		{
			string result = regex_replace(reg, pattern, string("$3"));
			strcpy(domain, (char*)result.c_str());
			strcpy(uri, "");
		}
		else
		{
			cout << "NOT MATCH" << endl;
			continue;
		}
		printf("add %s/%s\n", domain, uri);
		i = strlen(domain);
		j = strlen(uri);
		url = (PURL)malloc(sizeof(URL));
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1) * sizeof(char));
		url->uri = (char *)malloc((j + 1) * sizeof(char));
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];
		}
		url->domain[j] = '\0';

		BlackListInsert(blacklist, url);
	}

	fclose(file);
	return;

memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}


static BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len)
{
	//패킷 데이터를 분석해, 유해사이트인지 아닌지를 판단한다.
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str) + sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str) - 1) == 0)
	{
		i += sizeof(get_str) - 1;
	}
	else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0)
	{
		i += sizeof(post_str) - 1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str) - 1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str) - 1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str) - 1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		// Nice try...
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';

	printf("URL %s/%s: ", domain, uri);

	// Reverse the domain:
	for (i = 0; i < j / 2; i++)
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}

	// Search the blacklist:
	result = BlackListMatch(blacklist, &url);

	// Print the verdict:
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		puts("BLOCKED!");
		FILE *fp = fopen("log.txt", "a");
		char log[160];
		strcpy(log, "Blocked ");
		strcat(log, reverse(domain));
		strcat(log, "/");
		strcat(log, uri);
		strcat(log, "\n");
		fwrite(log, 1, strlen(log), fp);
		fclose(fp);
	}
	else
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;
}

/*
* URL comparison.
*/
static int __cdecl UrlCompare(const void *a, const void *b)
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);
}

/*
* URL matching
*/
static int UrlMatch(PURL urla, PURL urlb)
{
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}

static char* reverse(char* arr)
{
	char buf[1024];
	int i;
	for (i = 0; i < strlen(arr); i++)
	{
		buf[i] = arr[strlen(arr) - i - 1];
	}
	buf[i] = '\0';
	return buf;
}