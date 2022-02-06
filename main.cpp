#include <stdio.h> // printf
#include <errno.h> // EOK

#if defined(_MSC_VER)
#include <Winsock2.h>
#include <ws2ipdef.h> // IP_HDRINCL
#include <Windows.h>
#include "headers.h" // LPIPV4_HDR, LPUDP_HDR
#define EOK 0
#endif

// https://www.binarytides.com/raw-sockets-packets-with-winpcap/
// https://www.binarytides.com/raw-sockets-using-winsock/
// https://gist.github.com/austinmarton/1922600
// https://docs.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2#creating-a-raw-socket
// https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/

int main(int argc, char** argv)
{
#if defined(_MSC_VER)
	WORD const wWsaVersion = MAKEWORD(2, 2);
	WSADATA wsaData;

	if (WSAStartup(wWsaVersion, &wsaData) != EOK)
	{
		printf("WSAStartup failed\n");
		return EXIT_FAILURE;
	}

	/*DWORD dwBufferLen = 16384;
	LPWSAPROTOCOL_INFO const lpProtocolInfo = (LPWSAPROTOCOL_INFO)malloc(dwBufferLen);
	INT const iNumInfo = WSAEnumProtocols(NULL, lpProtocolInfo, &dwBufferLen);
	free(lpProtocolInfo);*/
#endif

	DWORD const BUF_MAX = 1200;
	CHAR buf[BUF_MAX] = {};
	DWORD dwPayload = 32;
	WORD wSrcePort = 8000, wDestPort = 8001;
	
	LPIPV4_HDR const iphdr = (LPIPV4_HDR)&buf[0];
	iphdr->ip_verlen = (4 << 4) | (sizeof(IPV4_HDR) / sizeof(ULONG));
	iphdr->ip_tos = 0;
	iphdr->ip_totallength = htons(sizeof(IPV4_HDR) + sizeof(UDP_HDR) + dwPayload);
	iphdr->ip_id = 0;
	iphdr->ip_offset = 0;
	iphdr->ip_ttl = 8; // Time-to-live is eight
	iphdr->ip_protocol = IPPROTO_UDP;
	iphdr->ip_checksum = 0;
	iphdr->ip_srcaddr = inet_addr("127.0.0.1");
	iphdr->ip_destaddr = inet_addr("127.0.0.1");
	// Calculate checksum for IPv4 header
	// The checksum() function computes the 16-bit one's
	// complement on the specified buffer. See the IPHDRINC
	// code sample on the companion CD for its implementation.
	//iphdr->ip_checksum = checksum(v4hdr, sizeof(IPV4_HDR));

	// Initialize the UDP header
	LPUDP_HDR const udphdr = (LPUDP_HDR)&buf[sizeof(IPV4_HDR)];
	udphdr->src_portno = htons(wSrcePort);
	udphdr->dst_portno = htons(wDestPort);
	udphdr->udp_length = htons(sizeof(UDP_HDR) + dwPayload);
	//udphdr->udp_checksum = 0;

	LPSTR const data = (LPSTR)&buf[sizeof(IPV4_HDR) + sizeof(UDP_HDR)];
	strcpy(data, "Hello RAW sockets");

	// Calculate the IPv4 and UDP pseudo-header checksum - this routine
	// extracts all the necessary fields from the headers and calculates
	// the checksum over it. See the iphdrinc sample for the implementation
	// of Ipv4PseudoHeaderChecksum().
	//udphdr->udp_checksum = Ipv4PseudoHeaderChecksum(v4hdr, udphdr, data, sizeof(IPV4_HDR) + sizeof(UDP_HDR) + dwPayload);

	// Открываем "сырой" сокет для отправки данных.
	int const sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // IPPROTO_UDP
	if (sock == -1)
	{
		printf("failed to create socket %d\n", sock);
		return EXIT_FAILURE;
	}

	// Сообщаем ОС что IP заголовок предоставим самостоятельно.
	INT iOptVal = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&iOptVal, sizeof(iOptVal));

	SOCKADDR_STORAGE addr = {};
	((SOCKADDR_IN *)&addr)->sin_family = AF_INET;
	//((SOCKADDR_IN *)&addr)->sin_port = udphdr->dst_portno;
	((SOCKADDR_IN *)&addr)->sin_addr.s_addr = iphdr->ip_destaddr;

	INT const iBytesSent = sendto(sock, buf, sizeof(IPV4_HDR) + sizeof(UDP_HDR) + dwPayload, 0, (SOCKADDR *)&addr, sizeof(addr));
	printf("%d bytes sent\n", iBytesSent);

#if defined(_MSC_VER)
	closesocket(sock);

	if (WSACleanup() != EOK)
	{
		printf("WSACleanup failed\n");
		return EXIT_FAILURE;
	}
#else
	close(sock);
#endif

	return EXIT_SUCCESS;
}
