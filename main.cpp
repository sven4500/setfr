#include <stdio.h> // printf
#include <errno.h> // EOK

#if defined(_MSC_VER)
#include <Winsock2.h>
#include <Windows.h>
#define EOK 0
#endif

// https://www.binarytides.com/raw-sockets-packets-with-winpcap/
// https://www.binarytides.com/raw-sockets-using-winsock/
// https://gist.github.com/austinmarton/1922600
// https://docs.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2#creating-a-raw-socket

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

	// Открываем "сырой" сокет для отправки данных.
	int const sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == -1)
	{
		printf("failed to create socket %d\n", sock);
		return EXIT_FAILURE;
	}

#if defined(_MSC_VER)
	closesocket(sock);

	if (WSACleanup() != EOK)
	{
		printf("WSACleanup failed\n");
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}
