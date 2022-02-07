#include <stdio.h> // printf
#include <errno.h> // EOK

#if defined(_MSC_VER)

#include <stdio.h> // fopen, fread
#include <stdint.h> // uint16_t, uint32_t
#include <Winsock2.h>
#include <ws2ipdef.h> // IP_HDRINCL
#include <Windows.h>
#include <errno.h> // EOK, ...
#include <getopt.h> // getopt, optarg
#include <headers.h> // LPIPV4_HDR, LPUDP_HDR

#define EOK 0

#elif defined(__linux__)

#include <stdlib.h> // EXIT_SUCCESS, EXIT_FAILUER
#include <stdint.h> // uint16_t, uint32_t
#include <string.h> // strcpy
#include <sys/socket.h> // socket, setsockopt
#include <arpa/inet.h> // inet_addr, htons
#include <unistd.h> // close
#include <headers.h>
#include <pthread.h>

#endif

/*void* udp_recv_thread(void*)
{
    int const sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(8001);
    int ret = bind(sock, (sockaddr *)&addr, sizeof(addr));
    usleep(500000);
    char buf[32] = {};
    int const size = recv(sock, buf, sizeof(buf), 0);
    return 0;
}*/

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
#endif

	char filename[MAX_PATH] = {};
	int c = 0, osi_level = 0, port = 0;

	while ((c = getopt(argc, argv, "hf:o:p:")) != -1)
	{
		switch (c)
		{
		case 'f':
			strcpy(filename, optarg);
			break;
		case 'o':
			osi_level = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'h':
			printf(
				"setfr (send Ethernet frame) utility\n"
				"-f [path] path to Ethernet frame containing file\n"
				"-o [2..4] OSI level\n"
				"-p [..65535] port number\n"
				"-h - print this message\n"
			);
			break;
		default:
			break;
		}
	}

	int const mtu = 1518;
	uint8_t frame_buf[mtu] = {};
	
	FILE* const fd = fopen(filename, "rb");

	if (fd == NULL)
	{
		printf("failed to open file\n");
		return EXIT_FAILURE;
	}

	fseek(fd, 0, SEEK_END);
	int const frame_size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	if (frame_size > mtu)
	{
		printf("Ethernet frame exceeds MTU\n");
		return EXIT_FAILURE;
	}

	fread(frame_buf, frame_size, 1, fd);
	fclose(fd);

	sockaddr_storage addr = {};
	int sock = -1;
	
	// Открываем сокет для отправки данных в соответствие с указанным уровнем OSI.
	if (osi_level == 2)
	{

	}
	else if (osi_level == 3)
	{
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // IPPROTO_UDP
		
		// Сообщаем ОС что IP заголовок предоставим самостоятельно.
		int optval = 1;
		setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval));

		((sockaddr_in *)&addr)->sin_family = AF_INET;
		//((sockaddr_in *)&addr)->sin_port = udphdr->dst_portno;
		((sockaddr_in *)&addr)->sin_addr.s_addr = htons(port);
	}
	else
	{
		printf("bad OSI level specified\n");
		return EXIT_FAILURE;
	}

	if (sock == -1)
	{
		printf("failed to create socket %d\n", sock);
		return EXIT_FAILURE;
	}

	int const bytes_sent = sendto(sock, (char*)frame_buf, frame_size, 0, (sockaddr *)&addr, sizeof(addr));
	printf("%d bytes sent\n", bytes_sent);

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
