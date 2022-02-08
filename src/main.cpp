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
#define PATH_MAX MAX_PATH

#elif defined(__linux__)

#include <stdlib.h> // EXIT_SUCCESS, EXIT_FAILUER
#include <stdint.h> // uint16_t, uint32_t
#include <string.h> // strcpy
#include <sys/socket.h> // socket, setsockopt
#include <arpa/inet.h> // inet_addr, htons
#include <linux/limits.h> // PATH_MAX
#include <linux/if_packet.h> // sockaddr_ll
#include <netinet/ether.h> // ether_header
#include <unistd.h> // close
#include <headers.h>
#include <pthread.h>

#endif

/*void* udp_recv_thread(void*)
{
    int const sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    //int const sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(8001);
    int ret = bind(sock, (sockaddr *)&addr, sizeof(addr));
    usleep(500000);
    char buf[74] = {};
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

	char filename[PATH_MAX] = {}, ipv4[20] = {};
	int c = 0, osi_level = 0, port = 0, dev_ind = 0;
	uint8_t dest_mac[6] = {};

	while ((c = getopt(argc, argv, "hf:o:i:p:d:m:")) != -1)
	{
		switch (c)
		{
		case 'f':
			strcpy(filename, optarg);
			break;
		case 'o':
			osi_level = atoi(optarg);
			break;
		case 'i':
			strcpy(ipv4, optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'd':
			dev_ind = atoi(optarg);
			break;
		case 'm':
			for(int i = 0; optarg[i]; ++i)
			{
				dest_mac[i/2] *= 16;
				dest_mac[i/2] += optarg[i] >= 'a' ? optarg[i] - 'a' + 10 : optarg[i] - '0';
			}
			break;
		case 'h':
			printf(
				"setfr (send Ethernet frame) utility\n"
				"-f [path] path to Ethernet frame containing file\n"
				"-o [2..4] OSI level\n"
				"-i [xxx.xxx.xxx.xxx] IPv4 address\n"
				"-p [..65535] port number\n"
				"-d [1..] index of network device\n"
				"-m [xx:xx:xx:xx:xx:xx] MAC address\n"
				"-h - print this message\n"
			);
			break;
		default:
			break;
		}
	}

	int const mtu = 1514; // 14+1500
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
#if defined(__linux__)
        sock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);

        /*struct ifreq if_idx;
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, "enp0s3", IFNAMSIZ-1);
        ioctl(sock, SIOCGIFINDEX, &if_idx);*/

        ((sockaddr_ll *)&addr)->sll_family = AF_PACKET;
        ((sockaddr_ll *)&addr)->sll_ifindex = dev_ind;
        ((sockaddr_ll *)&addr)->sll_halen = ETH_ALEN;
        ((sockaddr_ll *)&addr)->sll_addr[0] = dest_mac[0];
        ((sockaddr_ll *)&addr)->sll_addr[1] = dest_mac[1];
        ((sockaddr_ll *)&addr)->sll_addr[2] = dest_mac[2];
        ((sockaddr_ll *)&addr)->sll_addr[3] = dest_mac[3];
        ((sockaddr_ll *)&addr)->sll_addr[4] = dest_mac[4];
        ((sockaddr_ll *)&addr)->sll_addr[5] = dest_mac[5];
#endif
	}
	else if (osi_level == 3)
	{
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // IPPROTO_UDP
		
		// Сообщаем ОС что IP заголовок предоставим самостоятельно.
		int optval = 1;
		setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval));

		((sockaddr_in *)&addr)->sin_family = AF_INET;
		((sockaddr_in *)&addr)->sin_port = htons(port);
		// На UNIX-подобных системах inet_addr возвращает !0 на пустой строке.
		if(*ipv4)
			((sockaddr_in *)&addr)->sin_addr.s_addr = inet_addr(ipv4);
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
